package snowflake

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/connector"
	"github.com/spf13/cobra"
)

// envHelp describes the environment variables used by the Snowflake connector.
const envHelp = `Snowflake credentials (environment variables):
  SNOWFLAKE_ACCOUNT         - Account identifier (e.g. xy12345.us-east-1)
  SNOWFLAKE_USER            - Username
  SNOWFLAKE_PASSWORD        - Password for basic auth

  Key pair auth (JWT):
  SNOWFLAKE_PRIVATE_KEY_PATH - Path to RSA private key PEM file

  Programmatic access token (PAT):
  SNOWFLAKE_PAT             - Programmatic access token

  OAuth:
  SNOWFLAKE_TOKEN           - OAuth access token

  Optional:
  SNOWFLAKE_ROLE            - Role to assume (default: SECURITYADMIN)
  SNOWFLAKE_WAREHOUSE       - Warehouse for queries (default: COMPUTE_WH)
  SNOWFLAKE_DATABASE        - Database (default: SNOWFLAKE for ACCOUNT_USAGE views)`

func init() {
	connector.Register(
		"snowflake",
		func() collector.Collector { return &SnowflakeCollector{} },
		ConfigFromEnv,
		envHelp,
	)
}

// ConfigFromEnv builds a ConnectorConfig from Snowflake environment variables
// and CLI flags.
func ConfigFromEnv(cmd *cobra.Command) collector.ConnectorConfig {
	account := envOrFlag(cmd, "instance", "SNOWFLAKE_ACCOUNT")
	username := os.Getenv("SNOWFLAKE_USER")
	password := os.Getenv("SNOWFLAKE_PASSWORD")
	privateKeyPath := os.Getenv("SNOWFLAKE_PRIVATE_KEY_PATH")
	token := os.Getenv("SNOWFLAKE_TOKEN")
	pat := os.Getenv("SNOWFLAKE_PAT")
	role := os.Getenv("SNOWFLAKE_ROLE")
	warehouse := os.Getenv("SNOWFLAKE_WAREHOUSE")
	database := os.Getenv("SNOWFLAKE_DATABASE")

	authMethod := "basic"
	if privateKeyPath != "" {
		authMethod = "keypair"
	} else if pat != "" {
		authMethod = "pat"
	} else if token != "" {
		authMethod = "oauth"
	}

	// For OAuth/PAT, pass the token via Password field (gosnowflake convention).
	effectivePassword := password
	if authMethod == "oauth" {
		effectivePassword = token
	} else if authMethod == "pat" {
		effectivePassword = pat
	}

	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

	return collector.ConnectorConfig{
		Account:        account,
		InstanceURL:    account,
		AuthMethod:     authMethod,
		Username:       username,
		Password:       effectivePassword,
		PrivateKeyPath: privateKeyPath,
		Role:           role,
		Warehouse:      warehouse,
		Database:       database,
		Concurrency:    concurrency,
		RateLimit:      rateLimit,
	}
}

// envOrFlag returns the flag value if set, otherwise the environment variable.
func envOrFlag(cmd *cobra.Command, flag, env string) string {
	val, _ := cmd.Flags().GetString(flag)
	if val != "" {
		return val
	}
	return os.Getenv(env)
}

// querySpec defines a Snowflake security query to execute and its logical table name.
type querySpec struct {
	// Name is the logical name used in the snapshot (e.g. "users", "network_policies").
	Name string
	// Query is the SQL query to execute.
	Query string
}

// securityQueries lists all the Snowflake queries relevant for security auditing.
// These cover identity, access control, network security, and configuration.
var securityQueries = []querySpec{
	{
		Name:  "users",
		Query: "SHOW USERS",
	},
	{
		Name:  "roles",
		Query: "SHOW ROLES",
	},
	{
		Name:  "grants_to_users",
		Query: "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE DELETED_ON IS NULL",
	},
	{
		Name:  "grants_to_roles",
		Query: "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE DELETED_ON IS NULL",
	},
	{
		Name:  "network_policies",
		Query: "SHOW NETWORK POLICIES",
	},
	{
		Name:  "security_integrations",
		Query: "SHOW SECURITY INTEGRATIONS",
	},
	{
		Name:  "account_parameters",
		Query: "SHOW PARAMETERS IN ACCOUNT",
	},
	{
		Name:  "shares",
		Query: "SHOW SHARES",
	},
	{
		Name:  "login_history",
		Query: "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY WHERE EVENT_TIMESTAMP >= DATEADD('day', -30, CURRENT_TIMESTAMP()) ORDER BY EVENT_TIMESTAMP DESC LIMIT 10000",
	},
	{
		Name:  "password_policies",
		Query: "SHOW PASSWORD POLICIES",
	},
	{
		Name:  "session_policies",
		Query: "SHOW SESSION POLICIES",
	},
	{
		Name:  "warehouses",
		Query: "SHOW WAREHOUSES",
	},
	{
		Name:  "databases",
		Query: "SHOW DATABASES",
	},
	{
		Name:  "procedures",
		Query: "SELECT PROCEDURE_CATALOG, PROCEDURE_SCHEMA, PROCEDURE_NAME, PROCEDURE_LANGUAGE, PROCEDURE_DEFINITION FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES WHERE DELETED IS NULL",
	},
	{
		Name:  "functions",
		Query: "SELECT FUNCTION_CATALOG, FUNCTION_SCHEMA, FUNCTION_NAME, FUNCTION_LANGUAGE, FUNCTION_DEFINITION, IS_EXTERNAL FROM SNOWFLAKE.ACCOUNT_USAGE.FUNCTIONS WHERE DELETED IS NULL",
	},
}

// SnowflakeCollector implements the collector.Collector interface for Snowflake.
type SnowflakeCollector struct{}

// Name returns the platform name.
func (c *SnowflakeCollector) Name() string {
	return "snowflake"
}

// Tables returns the list of logical tables this collector will query.
func (c *SnowflakeCollector) Tables() []string {
	tables := make([]string, len(securityQueries))
	for i, q := range securityQueries {
		tables[i] = q.Name
	}
	return tables
}

// Collect connects to Snowflake and collects all security-relevant data.
func (c *SnowflakeCollector) Collect(ctx context.Context, config collector.ConnectorConfig) (*collector.Snapshot, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating Snowflake client: %w", err)
	}
	defer client.Close()

	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	instanceID := config.Account
	if instanceID == "" {
		instanceID = config.InstanceURL
	}
	snapshot := collector.NewSnapshot("snowflake", instanceID)

	// Collect queries in parallel with bounded concurrency.
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, concurrency)
		errs []error
	)

	for _, qs := range securityQueries {
		wg.Add(1)
		go func(spec querySpec) {
			defer wg.Done()

			// Acquire semaphore slot.
			sem <- struct{}{}
			defer func() { <-sem }()

			log.Printf("[collect] Executing query: %s", spec.Name)
			startTime := time.Now()

			records, err := client.Query(ctx, spec.Query)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("query %s: %w", spec.Name, err))
				mu.Unlock()
				log.Printf("[collect] ERROR querying %s: %v", spec.Name, err)
				return
			}

			td := &collector.TableData{
				Table:       spec.Name,
				Records:     records,
				Count:       len(records),
				CollectedAt: time.Now().UTC(),
			}

			mu.Lock()
			snapshot.AddTableData(td)
			mu.Unlock()

			log.Printf("[collect] Collected %d records from %s in %v", len(records), spec.Name, time.Since(startTime))
		}(qs)
	}

	wg.Wait()

	if len(errs) > 0 {
		// Log errors but don't fail the entire collection.
		// Some queries might not be accessible due to permissions.
		for _, e := range errs {
			log.Printf("[collect] Warning: %v", e)
		}
		snapshot.Metadata["collection_warnings"] = fmt.Sprintf("%d queries had errors", len(errs))
	}

	return snapshot, nil
}
