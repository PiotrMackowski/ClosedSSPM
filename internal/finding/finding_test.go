package finding

import (
	"testing"
)

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{Critical, 0},
		{High, 1},
		{Medium, 2},
		{Low, 3},
		{Info, 4},
		{Severity("UNKNOWN"), 5},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := SeverityOrder(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityOrder(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestSeverityOrderOrdering(t *testing.T) {
	// Critical should be more severe (lower number) than High, etc.
	if SeverityOrder(Critical) >= SeverityOrder(High) {
		t.Error("Critical should be more severe than High")
	}
	if SeverityOrder(High) >= SeverityOrder(Medium) {
		t.Error("High should be more severe than Medium")
	}
	if SeverityOrder(Medium) >= SeverityOrder(Low) {
		t.Error("Medium should be more severe than Low")
	}
	if SeverityOrder(Low) >= SeverityOrder(Info) {
		t.Error("Low should be more severe than Info")
	}
}

func TestCalculatePostureScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     string
	}{
		{
			name:     "no findings = A",
			findings: nil,
			want:     "A",
		},
		{
			name:     "empty findings = A",
			findings: []Finding{},
			want:     "A",
		},
		{
			name: "only info/low = A",
			findings: []Finding{
				{Severity: Info},
				{Severity: Low},
				{Severity: Low},
			},
			want: "A",
		},
		{
			name: "one medium = B",
			findings: []Finding{
				{Severity: Medium},
			},
			want: "B",
		},
		{
			name: "six mediums = C",
			findings: []Finding{
				{Severity: Medium},
				{Severity: Medium},
				{Severity: Medium},
				{Severity: Medium},
				{Severity: Medium},
				{Severity: Medium},
			},
			want: "C",
		},
		{
			name: "one high = C",
			findings: []Finding{
				{Severity: High},
			},
			want: "C",
		},
		{
			name: "four highs = D",
			findings: []Finding{
				{Severity: High},
				{Severity: High},
				{Severity: High},
				{Severity: High},
			},
			want: "D",
		},
		{
			name: "one critical = F",
			findings: []Finding{
				{Severity: Critical},
			},
			want: "F",
		},
		{
			name: "critical among others = F",
			findings: []Finding{
				{Severity: Low},
				{Severity: Medium},
				{Severity: High},
				{Severity: Critical},
			},
			want: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePostureScore(tt.findings)
			if got != tt.want {
				t.Errorf("CalculatePostureScore() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewSummary(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, Category: "ACL"},
		{Severity: High, Category: "Roles"},
		{Severity: High, Category: "ACL"},
		{Severity: Medium, Category: "Scripts"},
		{Severity: Low, Category: "ACL"},
		{Severity: Info, Category: "Users"},
	}

	s := NewSummary(findings)

	if s.Total != 6 {
		t.Errorf("Total = %d, want 6", s.Total)
	}

	// Check by severity counts.
	wantBySeverity := map[Severity]int{
		Critical: 1,
		High:     2,
		Medium:   1,
		Low:      1,
		Info:     1,
	}
	for sev, want := range wantBySeverity {
		if got := s.BySeverity[sev]; got != want {
			t.Errorf("BySeverity[%s] = %d, want %d", sev, got, want)
		}
	}

	// Check by category counts.
	wantByCategory := map[string]int{
		"ACL":     3,
		"Roles":   1,
		"Scripts": 1,
		"Users":   1,
	}
	for cat, want := range wantByCategory {
		if got := s.ByCategory[cat]; got != want {
			t.Errorf("ByCategory[%s] = %d, want %d", cat, got, want)
		}
	}

	// Has critical => F.
	if s.PostureScore != "F" {
		t.Errorf("PostureScore = %q, want %q", s.PostureScore, "F")
	}

	if s.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
}

func TestNewSummaryEmpty(t *testing.T) {
	s := NewSummary(nil)

	if s.Total != 0 {
		t.Errorf("Total = %d, want 0", s.Total)
	}
	if s.PostureScore != "A" {
		t.Errorf("PostureScore = %q, want %q", s.PostureScore, "A")
	}
}
