// Package collector defines the interfaces for SaaS data collection.
package collector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// DefaultConcurrency is the default number of parallel API requests for all connectors.
const DefaultConcurrency = 5

// Record represents a single record from a SaaS platform table/object.
type Record map[string]interface{}

// TableData holds the collected records for a single table.
type TableData struct {
	// Table is the name of the table (e.g. "sys_security_acl").
	Table string `json:"table"`
	// Records contains the collected records.
	Records []Record `json:"records"`
	// Count is the number of records collected.
	Count int `json:"count"`
	// CollectedAt is when this table was collected.
	CollectedAt time.Time `json:"collected_at"`
}

// Snapshot represents a point-in-time collection of data from a SaaS platform.
type Snapshot struct {
	// Platform identifies the SaaS platform (e.g. "servicenow").
	Platform string `json:"platform"`
	// InstanceURL is the URL of the instance that was audited.
	InstanceURL string `json:"instance_url"`
	// CollectedAt is when the snapshot was taken.
	CollectedAt time.Time `json:"collected_at"`
	// CollectedBy identifies who/what initiated the collection.
	CollectedBy string `json:"collected_by"`
	// Tables contains the collected data organized by table name.
	Tables map[string]*TableData `json:"tables"`
	// Metadata contains additional information about the collection.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewSnapshot creates a new empty snapshot.
func NewSnapshot(platform, instanceURL string) *Snapshot {
	return &Snapshot{
		Platform:    platform,
		InstanceURL: instanceURL,
		CollectedAt: time.Now().UTC(),
		CollectedBy: "closedsspm",
		Tables:      make(map[string]*TableData),
		Metadata:    make(map[string]string),
	}
}

// AddTableData adds collected table data to the snapshot.
func (s *Snapshot) AddTableData(td *TableData) {
	s.Tables[td.Table] = td
}

// GetRecords returns the records for a given table, or nil if not collected.
func (s *Snapshot) GetRecords(table string) []Record {
	td, ok := s.Tables[table]
	if !ok {
		return nil
	}
	return td.Records
}

// ConnectorConfig holds configuration for connecting to a SaaS platform.
type ConnectorConfig struct {
	// InstanceURL is the base URL of the instance.
	InstanceURL string
	// AuthMethod is the authentication method ("basic", "oauth", "keypair", or "apikey").
	AuthMethod string
	// Username for basic auth.
	Username string
	// Password for basic auth.
	Password string
	// APIKey for ServiceNow REST API key auth (x-sn-apikey header).
	APIKey string
	// ClientID for OAuth client credentials flow.
	ClientID string
	// ClientSecret for OAuth client credentials flow.
	ClientSecret string
	// PrivateKeyPath is the path to the RSA private key PEM file for key pair auth.
	PrivateKeyPath string
	// KeyID is the kid from the ServiceNow JWT Verifier Map.
	KeyID string
	// JWTUser is the ServiceNow username for the JWT sub claim (cannot be admin).
	JWTUser string
	// Concurrency is the max number of parallel API requests.
	Concurrency int
	// RateLimit is the max requests per second.
	RateLimit float64

	// --- Google Workspace fields ---

	// AccessToken is a raw OAuth2 bearer token (e.g. from gcloud auth print-access-token).
	// When set, the Google Workspace connector uses this instead of a Service Account JSON key.
	AccessToken string
	// CredentialsFile is the path to a service account JSON key file (e.g. for Google Workspace).
	CredentialsFile string
	// DelegatedUser is the super-admin email for domain-wide delegation (e.g. for Google Workspace).
	DelegatedUser string

	// --- Snowflake-specific fields ---

	// Account is the Snowflake account identifier (e.g. "xy12345.us-east-1").
	Account string
	// Warehouse is the Snowflake warehouse to use for queries.
	Warehouse string
	// Role is the Snowflake role to assume (e.g. SECURITYADMIN).
	Role string
	// Database is the Snowflake database (default: SNOWFLAKE for ACCOUNT_USAGE views).
	Database string
}

// Collector is the interface that all SaaS platform collectors must implement.
type Collector interface {
	// Name returns the name of the SaaS platform (e.g. "servicenow").
	Name() string
	// Collect connects to the SaaS platform and collects security-relevant data.
	Collect(ctx context.Context, config ConnectorConfig) (*Snapshot, error)
	// Tables returns the list of tables/objects this collector will query.
	Tables() []string
}

// CollectParallel runs fn for each table name in parallel with bounded concurrency,
// adding the resulting records to snapshot. Non-fatal errors are recorded in
// snapshot.Metadata["collection_warnings"]; the returned error is always nil to
// match the existing all-connectors behaviour of logging rather than aborting.
func CollectParallel(snapshot *Snapshot, concurrency int, tables []string, fn func(table string) ([]Record, error)) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, concurrency)
		errs []error
	)

	for _, table := range tables {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			log.Printf("[collect] Querying table: %s", name)
			start := time.Now()

			records, err := fn(name)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("table %s: %w", name, err))
				mu.Unlock()
				log.Printf("[collect] ERROR querying %s: %v", name, err)
				return
			}

			td := &TableData{
				Table:       name,
				Records:     records,
				Count:       len(records),
				CollectedAt: time.Now().UTC(),
			}

			mu.Lock()
			snapshot.AddTableData(td)
			mu.Unlock()

			log.Printf("[collect] Collected %d records from %s in %v", len(records), name, time.Since(start))
		}(table)
	}

	wg.Wait()

	if len(errs) > 0 {
		for _, e := range errs {
			log.Printf("[collect] Warning: %v", e)
		}
		snapshot.Metadata["collection_warnings"] = fmt.Sprintf("%d tables had errors", len(errs))
	}
}
