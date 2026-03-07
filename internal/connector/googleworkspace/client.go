package googleworkspace

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/option"
)

const (
	defaultConcurrency = 5
	defaultRateLimit   = 40.0
)

var nonAlphanumericUnderscore = regexp.MustCompile(`[^a-z0-9_]`)

type Client struct {
	directoryService *admin.Service
	reportsService   *reports.Service
	domain           string
	rateLimiter      *rate.Limiter
	concurrency      int
}

func NewClient(config collector.ConnectorConfig) (*Client, error) {
	var httpClient *http.Client
	var domain string

	switch {
	case config.AccessToken != "":
		// Direct OAuth2 access token — no GCP service account needed.
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: config.AccessToken,
		})
		httpClient = oauth2.NewClient(context.Background(), tokenSource)
		domain = extractDomain(config.DelegatedUser, config.InstanceURL)

	case config.CredentialsFile != "":
		if config.DelegatedUser == "" {
			return nil, fmt.Errorf("delegated user is required when using service account credentials")
		}

		credentialsJSON, err := os.ReadFile(config.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("reading credentials file: %w", err)
		}

		jwtConfig, err := google.JWTConfigFromJSON(
			credentialsJSON,
			"https://www.googleapis.com/auth/admin.directory.user.readonly",
			"https://www.googleapis.com/auth/admin.directory.user.security",
			"https://www.googleapis.com/auth/admin.reports.audit.readonly",
		)
		if err != nil {
			return nil, fmt.Errorf("parsing service account credentials: %w", err)
		}
		jwtConfig.Subject = config.DelegatedUser

		httpClient = jwtConfig.Client(context.Background())
		domain = extractDomain(config.DelegatedUser, config.InstanceURL)

	default:
		return nil, fmt.Errorf("either GW_ACCESS_TOKEN or GW_CREDENTIALS_FILE (+ GW_DELEGATED_USER) is required")
	}

	ctx := context.Background()

	directoryService, err := admin.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating directory service: %w", err)
	}

	reportsService, err := reports.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating reports service: %w", err)
	}

	rl := config.RateLimit
	if rl <= 0 {
		rl = defaultRateLimit
	}

	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	return &Client{
		directoryService: directoryService,
		reportsService:   reportsService,
		domain:           domain,
		rateLimiter:      rate.NewLimiter(rate.Limit(rl), 1),
		concurrency:      concurrency,
	}, nil
}

func (c *Client) ListUsers(ctx context.Context) ([]collector.Record, error) {
	if c.directoryService == nil {
		return nil, fmt.Errorf("directory service is not initialized")
	}
	call := c.directoryService.Users.List().Customer("my_customer")

	var out []collector.Record
	for {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		resp, err := call.Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}

		for _, u := range resp.Users {
			out = append(out, userToRecord(u))
		}

		if resp.NextPageToken == "" {
			break
		}
		call = call.PageToken(resp.NextPageToken)
	}

	return out, nil
}

func (c *Client) ListOAuthTokens(ctx context.Context, userKey string) ([]collector.Record, error) {
	if c.directoryService == nil {
		return nil, fmt.Errorf("directory service is not initialized")
	}
	if userKey == "" {
		return nil, fmt.Errorf("user key is required")
	}

	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	resp, err := c.directoryService.Tokens.List(userKey).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("listing OAuth tokens for user %q: %w", userKey, err)
	}

	out := make([]collector.Record, 0, len(resp.Items))
	for _, tok := range resp.Items {
		out = append(out, tokenToRecord(tok, userKey))
	}

	return out, nil
}

// ListAllTokens lists OAuth tokens for every user in the domain.
func (c *Client) ListAllTokens(ctx context.Context) ([]collector.Record, error) {
	users, err := c.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing users for token enumeration: %w", err)
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, c.concurrency)
		all []collector.Record
	)

	for _, u := range users {
		email, _ := u["primary_email"].(string)
		if email == "" {
			continue
		}

		wg.Add(1)
		go func(userKey string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tokens, listErr := c.ListOAuthTokens(ctx, userKey)
			if listErr != nil {
				log.Printf("[ListAllTokens] WARNING: user %s: %v", userKey, listErr)
				return
			}

			mu.Lock()
			all = append(all, tokens...)
			mu.Unlock()
		}(email)
	}

	wg.Wait()
	return all, nil
}

func (c *Client) ListTokenActivity(ctx context.Context) ([]collector.Record, error) {
	if c.reportsService == nil {
		return nil, fmt.Errorf("reports service is not initialized")
	}
	startTime := time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)
	call := c.reportsService.Activities.List("all", "token").StartTime(startTime)

	var out []collector.Record
	for {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		resp, err := call.Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("listing token activity: %w", err)
		}

		for _, activity := range resp.Items {
			out = append(out, activityToRecords(activity)...)
		}

		if resp.NextPageToken == "" {
			break
		}

		call = call.PageToken(resp.NextPageToken)
	}

	return out, nil
}

func extractDomain(jwtUser, fallback string) string {
	if parts := strings.Split(jwtUser, "@"); len(parts) == 2 && parts[1] != "" {
		return parts[1]
	}
	return strings.TrimSpace(fallback)
}

func userToRecord(u *admin.User) collector.Record {
	if u == nil {
		return collector.Record{}
	}

	fullName := ""
	if u.Name != nil {
		fullName = strings.TrimSpace(strings.TrimSpace(u.Name.GivenName) + " " + strings.TrimSpace(u.Name.FamilyName))
	}

	return collector.Record{
		"id":                 u.Id,
		"primary_email":      u.PrimaryEmail,
		"full_name":          fullName,
		"is_admin":           u.IsAdmin,
		"is_delegated_admin": u.IsDelegatedAdmin,
		"is_enrolled_in_2sv": u.IsEnrolledIn2Sv,
		"is_enforced_in_2sv": u.IsEnforcedIn2Sv,
		"suspended":          u.Suspended,
		"archived":           u.Archived,
		"org_unit_path":      u.OrgUnitPath,
		"last_login_time":    u.LastLoginTime,
		"creation_time":      u.CreationTime,
		"recovery_email":     u.RecoveryEmail,
	}
}

func tokenToRecord(tok *admin.Token, userKey string) collector.Record {
	if tok == nil {
		return collector.Record{"user_key": userKey}
	}

	return collector.Record{
		"user_key":     userKey,
		"client_id":    tok.ClientId,
		"display_text": tok.DisplayText,
		"anonymous":    tok.Anonymous,
		"native_app":   tok.NativeApp,
		"scopes":       strings.Join(tok.Scopes, " "),
		"all_scopes":   tok.Scopes,
		"scopes_count": len(tok.Scopes),
		"kind":         tok.Kind,
		"etag":         tok.Etag,
	}
}

func activityToRecords(activity *reports.Activity) []collector.Record {
	if activity == nil {
		return nil
	}

	customerID := ""
	uniqueQualifier := ""
	eventTime := ""
	applicationName := ""
	if activity.Id != nil {
		customerID = activity.Id.CustomerId
		uniqueQualifier = fmt.Sprintf("%d", activity.Id.UniqueQualifier)
		eventTime = activity.Id.Time
		applicationName = activity.Id.ApplicationName
	}

	actorEmail := ""
	actorProfileID := ""
	if activity.Actor != nil {
		actorEmail = activity.Actor.Email
		actorProfileID = activity.Actor.ProfileId
	}

	base := collector.Record{
		"application_name": applicationName,
		"customer_id":      customerID,
		"unique_qualifier": uniqueQualifier,
		"time":             eventTime,
		"actor_email":      actorEmail,
		"actor_profile_id": actorProfileID,
		"ip_address":       activity.IpAddress,
		"kind":             activity.Kind,
		"owner_domain":     activity.OwnerDomain,
	}

	if len(activity.Events) == 0 {
		record := cloneRecord(base)
		record["event_name"] = ""
		return []collector.Record{record}
	}

	out := make([]collector.Record, 0, len(activity.Events))
	for _, event := range activity.Events {
		record := cloneRecord(base)
		record["event_name"] = event.Name

		for _, p := range event.Parameters {
			k := "param_" + normalizeParameterName(p.Name)
			switch {
			case p.Value != "":
				record[k] = p.Value
			case p.BoolValue:
				record[k] = p.BoolValue
			case p.IntValue != 0:
				record[k] = p.IntValue
			case len(p.MultiValue) > 0:
				record[k] = strings.Join(p.MultiValue, ",")
			}
		}

		out = append(out, record)
	}

	return out
}

func cloneRecord(in collector.Record) collector.Record {
	out := make(collector.Record, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeParameterName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_", ":", "_")
	s = replacer.Replace(s)
	// Strip any character that is not alphanumeric or underscore.
	s = nonAlphanumericUnderscore.ReplaceAllString(s, "")
	s = strings.Trim(s, "_")
	if s == "" {
		return "unknown"
	}
	return s
}
