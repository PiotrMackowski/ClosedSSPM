package servicenow

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

// envHelp describes the environment variables used by the ServiceNow connector.
const envHelp = `ServiceNow credentials (environment variables):
  SNOW_INSTANCE      - Instance URL (e.g. https://mycompany.service-now.com)
  SNOW_USERNAME      - Username for basic auth
  SNOW_PASSWORD      - Password for basic auth
  SNOW_CLIENT_ID     - OAuth client ID (alternative to basic auth)
  SNOW_CLIENT_SECRET - OAuth client secret`

func init() {
	connector.Register(
		"servicenow",
		func() collector.Collector { return &ServiceNowCollector{} },
		ConfigFromEnv,
		envHelp,
	)
}

// ConfigFromEnv builds a ConnectorConfig from ServiceNow environment variables
// and CLI flags. This is the platform-specific config builder registered with
// the connector registry.
func ConfigFromEnv(cmd *cobra.Command) collector.ConnectorConfig {
	instance := envOrFlag(cmd, "instance", "SNOW_INSTANCE")
	username := os.Getenv("SNOW_USERNAME")
	password := os.Getenv("SNOW_PASSWORD")
	clientID := os.Getenv("SNOW_CLIENT_ID")
	clientSecret := os.Getenv("SNOW_CLIENT_SECRET")

	authMethod := "basic"
	if clientID != "" && clientSecret != "" {
		authMethod = "oauth"
	}

	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

	return collector.ConnectorConfig{
		InstanceURL:  instance,
		AuthMethod:   authMethod,
		Username:     username,
		Password:     password,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Concurrency:  concurrency,
		RateLimit:    rateLimit,
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

// tableSpec defines a ServiceNow table to collect and its relevant fields.
type tableSpec struct {
	Name   string
	Fields []string
}

// securityTables lists all the ServiceNow tables relevant for security auditing.
var securityTables = []tableSpec{
	{
		Name:   "sys_security_acl",
		Fields: []string{"sys_id", "name", "operation", "type", "condition", "script", "admin_overrides", "active", "description", "sys_updated_on"},
	},
	{
		Name:   "sys_security_acl_role",
		Fields: []string{"sys_id", "sys_security_acl", "sys_user_role"},
	},
	{
		Name:   "sys_user_role",
		Fields: []string{"sys_id", "name", "elevated_privilege", "assignable_by", "includes_roles", "description"},
	},
	{
		Name:   "sys_user_has_role",
		Fields: []string{"sys_id", "user", "role", "state", "granted_by", "inherited"},
	},
	{
		Name:   "sys_user_group",
		Fields: []string{"sys_id", "name", "roles", "active"},
	},
	{
		Name:   "sys_user",
		Fields: []string{"sys_id", "user_name", "name", "active", "locked_out", "last_login_time", "source", "web_service_access_only", "internal_integration_user"},
	},
	{
		Name:   "sys_script",
		Fields: []string{"sys_id", "name", "script", "when", "collection", "active", "description"},
	},
	{
		Name:   "sys_script_include",
		Fields: []string{"sys_id", "name", "script", "client_callable", "api_name", "active", "description"},
	},
	{
		Name:   "sys_ui_script",
		Fields: []string{"sys_id", "name", "script", "active", "global"},
	},
	{
		Name:   "sys_ws_definition",
		Fields: []string{"sys_id", "name", "active", "requires_authentication"},
	},
	{
		Name:   "sys_rest_message",
		Fields: []string{"sys_id", "name", "rest_endpoint", "authentication_type"},
	},
	{
		Name:   "oauth_entity",
		Fields: []string{"sys_id", "name", "type", "active", "client_id"},
	},
	{
		Name:   "sys_properties",
		Fields: []string{"sys_id", "name", "value", "description"},
	},
	{
		Name:   "sys_plugins",
		Fields: []string{"sys_id", "id", "name", "active"},
	},
	{
		Name:   "ecc_agent",
		Fields: []string{"sys_id", "name", "status", "validated"},
	},
	{
		Name:   "kb_knowledge",
		Fields: []string{"sys_id", "number", "short_description", "workflow_state", "kb_knowledge_base", "can_read_user_criteria"},
	},
	{
		Name:   "sc_cat_item",
		Fields: []string{"sys_id", "name", "active", "visible_standalone", "category"},
	},
	{
		Name:   "sys_ws_operation",
		Fields: []string{"sys_id", "name", "http_method", "requires_acl_authorization", "active", "web_service_definition", "operation_script"},
	},
	{
		Name:   "sys_certificate",
		Fields: []string{"sys_id", "name", "type", "expires", "active", "format"},
	},
	{
		Name:   "ldap_server_config",
		Fields: []string{"sys_id", "name", "server_url", "ssl", "active", "login_distinguished_name"},
	},
	{
		Name:   "saml2_update1",
		Fields: []string{"sys_id", "name", "active", "is_default", "signing_algorithm", "want_assertions_signed"},
	},
	{
		Name:   "sys_auth_profile",
		Fields: []string{"sys_id", "name", "type", "active"},
	},
	{
		Name:   "ip_address",
		Fields: []string{"sys_id", "ip_address", "ip_version", "type", "active"},
	},
}

// ServiceNowCollector implements the collector.Collector interface for ServiceNow.
type ServiceNowCollector struct{}

// Name returns the platform name.
func (c *ServiceNowCollector) Name() string {
	return "servicenow"
}

// Tables returns the list of tables this collector will query.
func (c *ServiceNowCollector) Tables() []string {
	tables := make([]string, len(securityTables))
	for i, t := range securityTables {
		tables[i] = t.Name
	}
	return tables
}

// Collect connects to ServiceNow and collects all security-relevant data.
func (c *ServiceNowCollector) Collect(ctx context.Context, config collector.ConnectorConfig) (*collector.Snapshot, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating ServiceNow client: %w", err)
	}

	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	snapshot := collector.NewSnapshot("servicenow", config.InstanceURL)

	// Collect tables in parallel with bounded concurrency.
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrency)
		errs    []error
	)

	for _, ts := range securityTables {
		wg.Add(1)
		go func(spec tableSpec) {
			defer wg.Done()

			// Acquire semaphore slot.
			sem <- struct{}{}
			defer func() { <-sem }()

			log.Printf("[collect] Querying table: %s", spec.Name)
			startTime := time.Now()

			records, err := client.QueryTable(ctx, spec.Name, spec.Fields)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("table %s: %w", spec.Name, err))
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
		}(ts)
	}

	wg.Wait()

	if len(errs) > 0 {
		// Log errors but don't fail the entire collection.
		// Some tables might not be accessible due to permissions.
		for _, e := range errs {
			log.Printf("[collect] Warning: %v", e)
		}
		snapshot.Metadata["collection_warnings"] = fmt.Sprintf("%d tables had errors", len(errs))
	}

	return snapshot, nil
}
