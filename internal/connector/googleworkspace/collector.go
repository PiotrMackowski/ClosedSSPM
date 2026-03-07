package googleworkspace

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

	return collector.ConnectorConfig{
		InstanceURL:     instance,
		AccessToken:     accessToken,
		CredentialsFile: credentialsFile,
		DelegatedUser:   delegatedUser,
		Concurrency:     concurrency,
		RateLimit:       rateLimit,
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

func (c *GoogleWorkspaceCollector) Collect(ctx context.Context, config collector.ConnectorConfig) (*collector.Snapshot, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating Google Workspace client: %w", err)
	}

	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	snapshot := collector.NewSnapshot("googleworkspace", config.InstanceURL)

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, concurrency)
		errs []error
	)

	for _, ts := range securityTables {
		wg.Add(1)
		go func(spec tableSpec) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			log.Printf("[collect] Querying table: %s", spec.Name)
			startTime := time.Now()

			var records []collector.Record
			var collectErr error
			switch spec.Name {
			case "users":
				records, collectErr = client.ListUsers(ctx)
			case "oauth_tokens":
				records, collectErr = client.ListAllTokens(ctx)
			case "token_activity":
				records, collectErr = client.ListTokenActivity(ctx)
			default:
				collectErr = fmt.Errorf("unsupported table %q", spec.Name)
			}

			if collectErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("table %s: %w", spec.Name, collectErr))
				mu.Unlock()
				log.Printf("[collect] ERROR querying %s: %v", spec.Name, collectErr)
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
		for _, e := range errs {
			log.Printf("[collect] Warning: %v", e)
		}
		snapshot.Metadata["collection_warnings"] = fmt.Sprintf("%d tables had errors", len(errs))
	}

	return snapshot, nil
}
