package snowflake

import (
	"context"
	"fmt"
	"os"

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
	account := connector.EnvOrFlag(cmd, "instance", "SNOWFLAKE_ACCOUNT")
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
		concurrency = collector.DefaultConcurrency
	}

	instanceID := config.Account
	if instanceID == "" {
		instanceID = config.InstanceURL
	}
	snapshot := collector.NewSnapshot("snowflake", instanceID)

	queryByName := make(map[string]string, len(securityQueries))
	tableNames := make([]string, len(securityQueries))
	for i, qs := range securityQueries {
		tableNames[i] = qs.Name
		queryByName[qs.Name] = qs.Query
	}

	collector.CollectParallel(snapshot, concurrency, tableNames, func(table string) ([]collector.Record, error) {
		return client.Query(ctx, queryByName[table])
	})

	return snapshot, nil
}
