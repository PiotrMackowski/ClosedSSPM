package entra

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/connector"
	"github.com/spf13/cobra"
)

const envHelp = `Microsoft Entra ID credentials (environment variables):
  ENTRA_TENANT_ID      - Azure AD tenant ID
  ENTRA_CLIENT_ID      - App registration client ID
  ENTRA_CLIENT_SECRET   - App registration client secret

Required API permissions (Application):
  Application.Read.All, Directory.Read.All`

func init() {
	connector.Register(
		"entra",
		func() collector.Collector { return &EntraCollector{} },
		ConfigFromEnv,
		envHelp,
	)
}

func ConfigFromEnv(cmd *cobra.Command) collector.ConnectorConfig {
	tenantID := envOrFlag(cmd, "instance", "ENTRA_TENANT_ID")
	clientID := os.Getenv("ENTRA_CLIENT_ID")
	clientSecret := os.Getenv("ENTRA_CLIENT_SECRET")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")
	return collector.ConnectorConfig{
		Account:      tenantID,
		InstanceURL:  "graph.microsoft.com",
		AuthMethod:   "oauth",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Concurrency:  concurrency,
		RateLimit:    rateLimit,
	}
}

func envOrFlag(cmd *cobra.Command, flag, env string) string {
	val, _ := cmd.Flags().GetString(flag)
	if val != "" {
		return val
	}
	return os.Getenv(env)
}

type tableSpec struct {
	Name string
}

var securityTables = []tableSpec{
	{Name: "app_registrations"},
	{Name: "service_principals"},
	{Name: "oauth2_permission_grants"},
	{Name: "app_role_assignments"},
	{Name: "app_credentials"},
}

type EntraCollector struct{}

func (c *EntraCollector) Name() string {
	return "entra"
}

func (c *EntraCollector) Tables() []string {
	tables := make([]string, len(securityTables))
	for i, t := range securityTables {
		tables[i] = t.Name
	}
	return tables
}

func (c *EntraCollector) Collect(ctx context.Context, config collector.ConnectorConfig) (*collector.Snapshot, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating Entra client: %w", err)
	}

	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	instanceID := config.Account
	if instanceID == "" {
		instanceID = config.InstanceURL
	}

	snapshot := collector.NewSnapshot("entra", instanceID)

	type cache struct {
		mu sync.Mutex

		apps      []collector.Record
		appsErr   error
		appsReady bool

		sps      []collector.Record
		spsErr   error
		spsReady bool

		grants      []collector.Record
		grantsErr   error
		grantsReady bool
	}

	cached := &cache{}

	getApps := func() ([]collector.Record, error) {
		cached.mu.Lock()
		if cached.appsReady {
			apps, err := cached.apps, cached.appsErr
			cached.mu.Unlock()
			return apps, err
		}
		cached.mu.Unlock()

		apps, err := client.ListApplications(ctx)

		cached.mu.Lock()
		cached.apps = apps
		cached.appsErr = err
		cached.appsReady = true
		cached.mu.Unlock()

		return apps, err
	}

	getSPs := func() ([]collector.Record, error) {
		cached.mu.Lock()
		if cached.spsReady {
			sps, err := cached.sps, cached.spsErr
			cached.mu.Unlock()
			return sps, err
		}
		cached.mu.Unlock()

		sps, err := client.ListServicePrincipals(ctx)

		cached.mu.Lock()
		cached.sps = sps
		cached.spsErr = err
		cached.spsReady = true
		cached.mu.Unlock()

		return sps, err
	}

	getGrants := func() ([]collector.Record, error) {
		cached.mu.Lock()
		if cached.grantsReady {
			grants, err := cached.grants, cached.grantsErr
			cached.mu.Unlock()
			return grants, err
		}
		cached.mu.Unlock()

		grants, err := client.ListOAuth2PermissionGrants(ctx)

		cached.mu.Lock()
		cached.grants = grants
		cached.grantsErr = err
		cached.grantsReady = true
		cached.mu.Unlock()

		return grants, err
	}

	collectTable := func(table string) ([]collector.Record, error) {
		now := time.Now().UTC()

		switch table {
		case "app_registrations":
			apps, err := getApps()
			if err != nil {
				return nil, err
			}
			sps, err := getSPs()
			if err != nil {
				return nil, err
			}

			permissionIDToName := make(map[string]string)
			latestSignInByAppID := make(map[string]time.Time)

			for _, sp := range sps {
				for _, rawRole := range asSlice(sp["appRoles"]) {
					role, ok := rawRole.(map[string]interface{})
					if !ok {
						continue
					}
					roleID := strings.ToLower(getString(role["id"]))
					roleValue := getString(role["value"])
					if roleID != "" && roleValue != "" {
						permissionIDToName[roleID] = roleValue
					}
				}

				for _, rawScope := range asSlice(sp["publishedPermissionScopes"]) {
					scope, ok := rawScope.(map[string]interface{})
					if !ok {
						continue
					}
					scopeID := strings.ToLower(getString(scope["id"]))
					scopeValue := getString(scope["value"])
					if scopeID != "" && scopeValue != "" {
						permissionIDToName[scopeID] = scopeValue
					}
				}

				appID := getString(sp["appId"])
				if appID == "" {
					continue
				}
				rawSignInActivity, ok := sp["signInActivity"].(map[string]interface{})
				if !ok {
					continue
				}
				lastSignIn := getString(rawSignInActivity["lastSignInDateTime"])
				if lastSignIn == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, lastSignIn)
				if err != nil {
					continue
				}
				if t.After(latestSignInByAppID[appID]) {
					latestSignInByAppID[appID] = t
				}
			}

			out := make([]collector.Record, 0, len(apps))
			for _, app := range apps {
				appObjectID := getString(app["id"])
				owners, err := client.ListApplicationOwners(ctx, appObjectID)
				if err != nil {
					return nil, fmt.Errorf("listing owners for application %s: %w", appObjectID, err)
				}

				ownerNames := make([]string, 0, len(owners))
				ownerIDs := make([]string, 0, len(owners))
				for _, owner := range owners {
					if id := getString(owner["id"]); id != "" {
						ownerIDs = append(ownerIDs, id)
					}
					name := getString(owner["displayName"])
					if name == "" {
						name = getString(owner["userPrincipalName"])
					}
					if name != "" {
						ownerNames = append(ownerNames, name)
					}
				}

				permissionSet := make(map[string]struct{})
				for _, rawRRA := range asSlice(app["requiredResourceAccess"]) {
					rra, ok := rawRRA.(map[string]interface{})
					if !ok {
						continue
					}
					for _, rawAccess := range asSlice(rra["resourceAccess"]) {
						access, ok := rawAccess.(map[string]interface{})
						if !ok {
							continue
						}
						accessID := strings.ToLower(getString(access["id"]))
						if accessID == "" {
							continue
						}
						name := permissionIDToName[accessID]
						if name == "" {
							name = accessID
						}
						permissionSet[name] = struct{}{}
					}
				}

				permissions := make([]string, 0, len(permissionSet))
				for permission := range permissionSet {
					permissions = append(permissions, permission)
				}
				sort.Strings(permissions)

				appID := getString(app["appId"])
				lastSignIn := latestSignInByAppID[appID]
				hasRecentSignIn := !lastSignIn.IsZero() && now.Sub(lastSignIn) <= 90*24*time.Hour

				record := collector.Record{
					"id":                       appObjectID,
					"appId":                    appID,
					"displayName":              getString(app["displayName"]),
					"signInAudience":           getString(app["signInAudience"]),
					"owner_count":              len(owners),
					"owner_names":              strings.Join(ownerNames, ";"),
					"owner_ids":                strings.Join(ownerIDs, ";"),
					"required_permissions":     strings.Join(permissions, ","),
					"multi_tenant":             getString(app["signInAudience"]) != "AzureADMyOrg",
					"has_password_credentials": len(asSlice(app["passwordCredentials"])) > 0,
					"has_key_credentials":      len(asSlice(app["keyCredentials"])) > 0,
					"has_credentials":          len(asSlice(app["passwordCredentials"]))+len(asSlice(app["keyCredentials"])) > 0,
					"has_recent_signin":        hasRecentSignIn,
				}
				if !lastSignIn.IsZero() {
					record["last_sign_in_at"] = lastSignIn.UTC().Format(time.RFC3339)
				}
				out = append(out, record)
			}
			return out, nil

		case "service_principals":
			sps, err := getSPs()
			if err != nil {
				return nil, err
			}
			grants, err := getGrants()
			if err != nil {
				return nil, err
			}

			grantCountByClientID := make(map[string]int)
			for _, grant := range grants {
				clientID := getString(grant["clientId"])
				if clientID == "" {
					continue
				}
				grantCountByClientID[clientID]++
			}

			out := make([]collector.Record, 0, len(sps))
			for _, sp := range sps {
				spID := getString(sp["id"])
				record := collector.Record{
					"id":                          spID,
					"appId":                       getString(sp["appId"]),
					"displayName":                 getString(sp["displayName"]),
					"accountEnabled":              sp["accountEnabled"],
					"appRoleAssignmentRequired":   sp["appRoleAssignmentRequired"],
					"servicePrincipalType":        getString(sp["servicePrincipalType"]),
					"oauth2_grant_count":          grantCountByClientID[spID],
					"has_oauth2_grants":           grantCountByClientID[spID] > 0,
					"user_assignment_required":    sp["appRoleAssignmentRequired"],
					"disabled_with_active_grants": (sp["accountEnabled"] == false) && grantCountByClientID[spID] > 0,
				}
				rawSignInActivity, ok := sp["signInActivity"].(map[string]interface{})
				if ok {
					record["lastSignInDateTime"] = getString(rawSignInActivity["lastSignInDateTime"])
				}
				out = append(out, record)
			}
			return out, nil

		case "oauth2_permission_grants":
			return getGrants()

		case "app_role_assignments":
			sps, err := getSPs()
			if err != nil {
				return nil, err
			}
			out := make([]collector.Record, 0)
			for _, sp := range sps {
				spID := getString(sp["id"])
				if spID == "" {
					continue
				}
				assignments, err := client.ListAppRoleAssignments(ctx, spID)
				if err != nil {
					return nil, fmt.Errorf("listing app role assignments for service principal %s: %w", spID, err)
				}
				for _, assignment := range assignments {
					record := collector.Record{}
					for k, v := range assignment {
						record[k] = v
					}
					record["servicePrincipalId"] = spID
					record["servicePrincipalAppId"] = getString(sp["appId"])
					record["servicePrincipalDisplayName"] = getString(sp["displayName"])
					out = append(out, record)
				}
			}
			return out, nil

		case "app_credentials":
			apps, err := getApps()
			if err != nil {
				return nil, err
			}
			out := make([]collector.Record, 0)
			for _, app := range apps {
				creds := credentialsFromApplicationRecord(app)
				for _, cred := range creds {
					start := getString(cred["start_date_time"])
					end := getString(cred["end_date_time"])

					isExpired := false
					validOverOneYear := false

					endTime, endErr := time.Parse(time.RFC3339, end)
					if endErr == nil {
						isExpired = endTime.Before(now)
					}

					startTime, startErr := time.Parse(time.RFC3339, start)
					if startErr == nil && endErr == nil {
						validOverOneYear = endTime.Sub(startTime) > 365*24*time.Hour
					}

					cred["is_expired"] = isExpired
					cred["valid_over_1y"] = validOverOneYear
					cred["uses_password"] = getString(cred["credential_type"]) == "password"
					out = append(out, cred)
				}
			}
			return out, nil
		}

		return nil, fmt.Errorf("unsupported table %s", table)
	}

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

			start := time.Now()
			log.Printf("[collect] Querying table: %s", spec.Name)

			records, err := collectTable(spec.Name)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("table %s: %w", spec.Name, err))
				mu.Unlock()
				log.Printf("[collect] ERROR querying %s: %v", spec.Name, err)
				return
			}

			td := &collector.TableData{Table: spec.Name, Records: records, Count: len(records), CollectedAt: time.Now().UTC()}
			mu.Lock()
			snapshot.AddTableData(td)
			mu.Unlock()
			log.Printf("[collect] Collected %d records from %s in %v", len(records), spec.Name, time.Since(start))
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
