// Package snowflake implements the Snowflake SQL client and collector.
package snowflake

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	sf "github.com/snowflakedb/gosnowflake"
)

const (
	// version is used in the application name sent to Snowflake.
	version = "0.1.0"

	// defaultRole is the Snowflake role assumed when none is specified.
	defaultRole = "SECURITYADMIN"

	// defaultDatabase is used for ACCOUNT_USAGE views.
	defaultDatabase = "SNOWFLAKE"

	// defaultWarehouse is used when no warehouse is specified.
	defaultWarehouse = "COMPUTE_WH"

	// queryTimeout limits individual query execution.
	queryTimeout = 60 * time.Second
)

// Client is the Snowflake SQL client used for security data collection.
type Client struct {
	db      *sql.DB
	account string
}

// NewClient creates a new Snowflake client from the connector config.
func NewClient(config *SnowflakeConfig) (*Client, error) {
	account := config.Account
	if account == "" {
		// Fall back to InstanceURL if Account is not set.
		account = config.GetInstanceURL()
	}
	if account == "" {
		return nil, fmt.Errorf("snowflake account identifier is required (set SNOWFLAKE_ACCOUNT)")
	}
	// Strip any https:// prefix or trailing slashes — account is just the identifier.
	account = strings.TrimPrefix(account, "https://")
	account = strings.TrimPrefix(account, "http://")
	account = strings.TrimSuffix(account, "/")
	account = strings.TrimSuffix(account, ".snowflakecomputing.com")

	role := config.Role
	if role == "" {
		role = defaultRole
	}
	database := config.Database
	if database == "" {
		database = defaultDatabase
	}
	warehouse := config.Warehouse
	if warehouse == "" {
		warehouse = defaultWarehouse
	}

	sfConfig := &sf.Config{
		Account:        account,
		User:           config.Username,
		Role:           role,
		Database:       database,
		Warehouse:      warehouse,
		Application:    "ClosedSSPM/" + version,
		LoginTimeout:   30 * time.Second,
		RequestTimeout: queryTimeout,
	}

	// Configure authentication method.
	switch config.AuthMethod {
	case "basic", "":
		if config.Username == "" || config.Password == "" {
			return nil, fmt.Errorf("username and password are required for basic auth")
		}
		sfConfig.Password = config.Password
	case "keypair":
		if config.Username == "" {
			return nil, fmt.Errorf("username is required for key pair auth")
		}
		if config.PrivateKeyPath == "" {
			return nil, fmt.Errorf("private key path is required for key pair auth")
		}
		pk, err := loadPrivateKey(config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading private key: %w", err)
		}
		sfConfig.Authenticator = sf.AuthTypeJwt
		sfConfig.PrivateKey = pk
	case "oauth":
		if config.Password == "" {
			// For OAuth, the access token is passed via Password field (standard gosnowflake convention).
			return nil, fmt.Errorf("OAuth access token is required (set SNOWFLAKE_TOKEN)")
		}
		sfConfig.Authenticator = sf.AuthTypeOAuth
		sfConfig.Token = config.Password
	case "pat":
		if config.Username == "" {
			return nil, fmt.Errorf("username is required for PAT auth")
		}
		if config.Password == "" {
			return nil, fmt.Errorf("PAT token is required (set SNOWFLAKE_PAT)")
		}
		sfConfig.Authenticator = sf.AuthTypePat
		sfConfig.Token = config.Password
	default:
		return nil, fmt.Errorf("unsupported auth method: %s (use basic, keypair, oauth, or pat)", config.AuthMethod)
	}

	dsn, err := sf.DSN(sfConfig)
	if err != nil {
		return nil, fmt.Errorf("building Snowflake DSN: %w", err)
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening Snowflake connection: %w", err)
	}

	// Verify connectivity.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to Snowflake: %w", err)
	}

	return &Client{db: db, account: account}, nil
}

// Close closes the underlying database connection.
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Query executes a SQL query and returns the results as collector.Record slices.
// Each row becomes a Record with column names as keys.
func (c *Client) Query(ctx context.Context, query string) ([]collector.Record, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("executing query: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("getting columns: %w", err)
	}

	var records []collector.Record
	for rows.Next() {
		// Create scan targets as interface{} pointers.
		values := make([]interface{}, len(columns))
		ptrs := make([]interface{}, len(columns))
		for i := range values {
			ptrs[i] = &values[i]
		}

		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		record := make(collector.Record)
		for i, col := range columns {
			record[strings.ToLower(col)] = normalizeValue(values[i])
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return records, nil
}

// normalizeValue converts SQL driver values to JSON-friendly types.
func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(val)
	case time.Time:
		return val.UTC().Format(time.RFC3339)
	default:
		return val
	}
}

// loadPrivateKey reads and parses an RSA private key from a PEM file.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try PKCS#8 first (modern format), fall back to PKCS#1.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
