package servicenow

import (
	"context"
	"fmt"
	"os"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/connector"
	"github.com/spf13/cobra"
)

// envHelp describes the environment variables used by the ServiceNow connector.
const envHelp = `ServiceNow credentials (environment variables):
  SNOW_INSTANCE         - Instance URL (e.g. https://mycompany.service-now.com)
  SNOW_USERNAME         - Username for basic auth
  SNOW_PASSWORD         - Password for basic auth
  SNOW_API_KEY          - REST API key (alternative to basic auth; x-sn-apikey header)
  SNOW_CLIENT_ID        - OAuth client ID (alternative to basic auth)
  SNOW_CLIENT_SECRET    - OAuth client secret

  Key pair auth (JWT bearer grant):
  SNOW_PRIVATE_KEY_PATH - Path to RSA private key PEM file
  SNOW_KEY_ID           - kid from ServiceNow JWT Verifier Map
  SNOW_JWT_USER         - ServiceNow username for JWT sub claim (cannot be admin)`

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
	instance := connector.EnvOrFlag(cmd, "instance", "SNOW_INSTANCE")
	username := os.Getenv("SNOW_USERNAME")
	password := os.Getenv("SNOW_PASSWORD")
	apiKey := os.Getenv("SNOW_API_KEY")
	clientID := os.Getenv("SNOW_CLIENT_ID")
	clientSecret := os.Getenv("SNOW_CLIENT_SECRET")
	privateKeyPath := os.Getenv("SNOW_PRIVATE_KEY_PATH")
	keyID := os.Getenv("SNOW_KEY_ID")
	jwtUser := os.Getenv("SNOW_JWT_USER")

	authMethod := "basic"
	if apiKey != "" {
		authMethod = "apikey"
	} else if privateKeyPath != "" && clientID != "" && clientSecret != "" {
		authMethod = "keypair"
	} else if clientID != "" && clientSecret != "" {
		authMethod = "oauth"
	}

	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

	return collector.ConnectorConfig{
		InstanceURL:    instance,
		AuthMethod:     authMethod,
		Username:       username,
		Password:       password,
		APIKey:         apiKey,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		PrivateKeyPath: privateKeyPath,
		KeyID:          keyID,
		JWTUser:        jwtUser,
		Concurrency:    concurrency,
		RateLimit:      rateLimit,
	}
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
		Name:   "ip_access",
		Fields: []string{"sys_id", "range_start", "range_end", "type", "active", "description", "flow", "ports"},
	},
	{
		Name:   "ecc_agent_script_file",
		Fields: []string{"sys_id", "name", "script", "script_name", "active", "sys_updated_on"},
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
		concurrency = collector.DefaultConcurrency
	}

	snapshot := collector.NewSnapshot("servicenow", config.InstanceURL)

	fieldsByTable := make(map[string][]string, len(securityTables))
	tableNames := make([]string, len(securityTables))
	for i, ts := range securityTables {
		tableNames[i] = ts.Name
		fieldsByTable[ts.Name] = ts.Fields
	}

	collector.CollectParallel(snapshot, concurrency, tableNames, func(table string) ([]collector.Record, error) {
		return client.QueryTable(ctx, table, fieldsByTable[table])
	})

	return snapshot, nil
}
