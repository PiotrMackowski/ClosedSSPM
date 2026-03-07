package entra

import (
	"context"
	"fmt"
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

type EntraConfig struct {
	collector.BaseConfig
	TenantID     string
	AuthMethod   string
	ClientID     string
	ClientSecret string
}

func ConfigFromEnv(cmd *cobra.Command) collector.ConnectorConfig {
	tenantID := connector.EnvOrFlag(cmd, "instance", "ENTRA_TENANT_ID")
	clientID := os.Getenv("ENTRA_CLIENT_ID")
	clientSecret := os.Getenv("ENTRA_CLIENT_SECRET")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")
	return &EntraConfig{
		BaseConfig: collector.BaseConfig{
			InstanceURL: "graph.microsoft.com",
			Concurrency: concurrency,
			RateLimit:   rateLimit,
		},
		TenantID:     tenantID,
		AuthMethod:   "oauth",
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
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

type collectionContext struct {
	client *Client
	ctx    context.Context

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

func (cc *collectionContext) getApps() ([]collector.Record, error) {
	cc.mu.Lock()
	if cc.appsReady {
		apps, err := cc.apps, cc.appsErr
		cc.mu.Unlock()
		return apps, err
	}
	cc.mu.Unlock()

	apps, err := cc.client.ListApplications(cc.ctx)

	cc.mu.Lock()
	cc.apps = apps
	cc.appsErr = err
	cc.appsReady = true
	cc.mu.Unlock()

	return apps, err
}

func (cc *collectionContext) getSPs() ([]collector.Record, error) {
	cc.mu.Lock()
	if cc.spsReady {
		sps, err := cc.sps, cc.spsErr
		cc.mu.Unlock()
		return sps, err
	}
	cc.mu.Unlock()

	sps, err := cc.client.ListServicePrincipals(cc.ctx)

	cc.mu.Lock()
	cc.sps = sps
	cc.spsErr = err
	cc.spsReady = true
	cc.mu.Unlock()

	return sps, err
}

func (cc *collectionContext) getGrants() ([]collector.Record, error) {
	cc.mu.Lock()
	if cc.grantsReady {
		grants, err := cc.grants, cc.grantsErr
		cc.mu.Unlock()
		return grants, err
	}
	cc.mu.Unlock()

	grants, err := cc.client.ListOAuth2PermissionGrants(cc.ctx)

	cc.mu.Lock()
	cc.grants = grants
	cc.grantsErr = err
	cc.grantsReady = true
	cc.mu.Unlock()

	return grants, err
}

func (c *EntraCollector) collectAppRegistrations(cc *collectionContext) ([]collector.Record, error) {
	now := time.Now().UTC()

	apps, err := cc.getApps()
	if err != nil {
		return nil, err
	}
	sps, err := cc.getSPs()
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
		owners, err := cc.client.ListApplicationOwners(cc.ctx, appObjectID)
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
}

func (c *EntraCollector) collectServicePrincipals(cc *collectionContext) ([]collector.Record, error) {
	sps, err := cc.getSPs()
	if err != nil {
		return nil, err
	}
	grants, err := cc.getGrants()
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
}

func (c *EntraCollector) collectAppRoleAssignments(cc *collectionContext) ([]collector.Record, error) {
	sps, err := cc.getSPs()
	if err != nil {
		return nil, err
	}
	out := make([]collector.Record, 0)
	for _, sp := range sps {
		spID := getString(sp["id"])
		if spID == "" {
			continue
		}
		assignments, err := cc.client.ListAppRoleAssignments(cc.ctx, spID)
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
}

func (c *EntraCollector) collectAppCredentials(cc *collectionContext) ([]collector.Record, error) {
	now := time.Now().UTC()

	apps, err := cc.getApps()
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

func (c *EntraCollector) Collect(ctx context.Context, cfg collector.ConnectorConfig) (*collector.Snapshot, error) {
	config, ok := cfg.(*EntraConfig)
	if !ok {
		return nil, fmt.Errorf("entra collector requires *EntraConfig, got %T", cfg)
	}

	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating Entra client: %w", err)
	}

	concurrency := config.GetConcurrency()
	if concurrency <= 0 {
		concurrency = collector.DefaultConcurrency
	}

	instanceID := config.TenantID
	if instanceID == "" {
		instanceID = config.GetInstanceURL()
	}

	snapshot := collector.NewSnapshot("entra", instanceID)

	cc := &collectionContext{client: client, ctx: ctx}

	collectTable := func(table string) ([]collector.Record, error) {
		switch table {
		case "app_registrations":
			return c.collectAppRegistrations(cc)

		case "service_principals":
			return c.collectServicePrincipals(cc)

		case "oauth2_permission_grants":
			return cc.getGrants()

		case "app_role_assignments":
			return c.collectAppRoleAssignments(cc)

		case "app_credentials":
			return c.collectAppCredentials(cc)
		}

		return nil, fmt.Errorf("unsupported table %s", table)
	}

	tableNames := make([]string, len(securityTables))
	for i, t := range securityTables {
		tableNames[i] = t.Name
	}

	collector.CollectParallel(snapshot, concurrency, tableNames, collectTable)

	return snapshot, nil
}
