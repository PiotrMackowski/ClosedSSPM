package googleworkspace

import (
	"context"
	"fmt"
	"os"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/connector"
	"github.com/spf13/cobra"
)

const envHelp = `Google Workspace credentials (environment variables):
  GW_ACCESS_TOKEN     - OAuth2 bearer token (e.g. from gcloud auth print-access-token)
  GW_CREDENTIALS_FILE - Path to service account JSON key file (fallback)
  GW_DELEGATED_USER   - Super admin email for domain-wide delegation (with service account)`

func init() {
	connector.Register(
		"googleworkspace",
		func() collector.Collector { return &GoogleWorkspaceCollector{} },
		ConfigFromEnv,
		envHelp,
	)
}

type GoogleWorkspaceConfig struct {
	collector.BaseConfig
	AccessToken     string
	CredentialsFile string
	DelegatedUser   string
}

func ConfigFromEnv(cmd *cobra.Command) collector.ConnectorConfig {
	accessToken := os.Getenv("GW_ACCESS_TOKEN")
	credentialsFile := os.Getenv("GW_CREDENTIALS_FILE")
	delegatedUser := os.Getenv("GW_DELEGATED_USER")
	instance := connector.EnvOrFlag(cmd, "instance", "GW_INSTANCE")
	if instance == "" {
		instance = "googleapis.com"
	}

	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

	return &GoogleWorkspaceConfig{
		BaseConfig: collector.BaseConfig{
			InstanceURL: instance,
			Concurrency: concurrency,
			RateLimit:   rateLimit,
		},
		AccessToken:     accessToken,
		CredentialsFile: credentialsFile,
		DelegatedUser:   delegatedUser,
	}
}

type tableSpec struct {
	Name string
}

var securityTables = []tableSpec{
	{Name: "users"},
	{Name: "oauth_tokens"},
	{Name: "token_activity"},
}

type GoogleWorkspaceCollector struct{}

func (c *GoogleWorkspaceCollector) Name() string {
	return "googleworkspace"
}

func (c *GoogleWorkspaceCollector) Tables() []string {
	tables := make([]string, len(securityTables))
	for i, t := range securityTables {
		tables[i] = t.Name
	}
	return tables
}

func (c *GoogleWorkspaceCollector) Collect(ctx context.Context, cfg collector.ConnectorConfig) (*collector.Snapshot, error) {
	config, ok := cfg.(*GoogleWorkspaceConfig)
	if !ok {
		return nil, fmt.Errorf("googleworkspace collector requires *GoogleWorkspaceConfig, got %T", cfg)
	}

	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating Google Workspace client: %w", err)
	}

	concurrency := config.GetConcurrency()
	if concurrency <= 0 {
		concurrency = collector.DefaultConcurrency
	}

	snapshot := collector.NewSnapshot("googleworkspace", config.GetInstanceURL())

	tableNames := make([]string, len(securityTables))
	for i, t := range securityTables {
		tableNames[i] = t.Name
	}

	collector.CollectParallel(snapshot, concurrency, tableNames, func(table string) ([]collector.Record, error) {
		switch table {
		case "users":
			return client.ListUsers(ctx)
		case "oauth_tokens":
			return client.ListAllTokens(ctx)
		case "token_activity":
			return client.ListTokenActivity(ctx)
		default:
			return nil, fmt.Errorf("unsupported table %q", table)
		}
	})

	return snapshot, nil
}
