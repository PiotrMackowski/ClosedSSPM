// Package collector defines the interfaces for SaaS data collection.
package collector

import (
	"context"
	"fmt"
	"log/slog"
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

// ConnectorConfig is the interface that all per-connector configs must implement.
type ConnectorConfig interface {
	GetInstanceURL() string
	GetConcurrency() int
	GetRateLimit() float64
}

// BaseConfig holds fields shared by every connector.
type BaseConfig struct {
	InstanceURL string
	Concurrency int
	RateLimit   float64
}

func (b BaseConfig) GetInstanceURL() string { return b.InstanceURL }
func (b BaseConfig) GetConcurrency() int    { return b.Concurrency }
func (b BaseConfig) GetRateLimit() float64  { return b.RateLimit }

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

			slog.Info("Querying table", "table", name)
			start := time.Now()

			records, err := fn(name)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("table %s: %w", name, err))
				mu.Unlock()
				slog.Error("Query failed", "table", name, "err", err)
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

			slog.Info("Collected records", "table", name, "count", len(records), "duration", time.Since(start))
		}(table)
	}

	wg.Wait()

	if len(errs) > 0 {
		for _, e := range errs {
			slog.Warn("Collection warning", "err", e)
		}
		snapshot.Metadata["collection_warnings"] = fmt.Sprintf("%d tables had errors", len(errs))
	}
}
