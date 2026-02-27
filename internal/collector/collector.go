// Package collector defines the interfaces for SaaS data collection.
package collector

import (
	"context"
	"time"
)

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
	// AuthMethod is the authentication method ("basic" or "oauth").
	AuthMethod string
	// Username for basic auth.
	Username string
	// Password for basic auth.
	Password string
	// ClientID for OAuth client credentials flow.
	ClientID string
	// ClientSecret for OAuth client credentials flow.
	ClientSecret string
	// Concurrency is the max number of parallel API requests.
	Concurrency int
	// RateLimit is the max requests per second.
	RateLimit float64
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
