package scanner

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestScanString(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		matchRule   string
	}{
		{
			name:        "AWS Access Key",
			input:       "AKIAIOSFODNN7EXAMPLE",
			shouldMatch: true,
			matchRule:   "AWS Access Key ID",
		},
		{
			name:        "GitHub PAT",
			input:       "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
			shouldMatch: true,
			matchRule:   "GitHub Personal Access Token",
		},
		{
			name:        "Slack Webhook",
			input:       "https://hooks.slack.com/services/T12345678/B12345678/" + "1234567890abcdefghijklmn",
			shouldMatch: true,
			matchRule:   "Slack Webhook URL",
		},
		{
			name:        "Private Key",
			input:       "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
			shouldMatch: true,
			matchRule:   "Private Key",
		},
		{
			name:        "Normal string",
			input:       "just-some-harmless-string",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, found := ScanString(tt.input)
			if found != tt.shouldMatch {
				t.Errorf("expected found=%v, got=%v for input=%s", tt.shouldMatch, found, tt.input)
			}
			if found && tt.shouldMatch {
				if len(findings) == 0 || findings[0].RuleName != tt.matchRule {
					t.Errorf("expected rule %q, got %q", tt.matchRule, findings[0].RuleName)
				}
			}
		})
	}
}

func TestScanContainer(t *testing.T) {
	container := corev1.Container{
		Name: "test-container",
		Env: []corev1.EnvVar{
			{
				Name:  "SAFE_ENV",
				Value: "safe-value",
			},
			{
				Name:  "DATABASE_PASSWORD",
				Value: "super-secret-password-123",
			},
			{
				Name:  "AWS_ACCESS_KEY_ID",
				Value: "AKIAIOSFODNN7EXAMPLE",
			},
			{
				Name:  "PORT",
				Value: "8080", // short, shouldn't flag
			},
			{
				Name:  "REF_PWD",
				Value: "$(OTHER_VAR)", // reference, shouldn't flag
			},
		},
		Command: []string{"/bin/sh", "-c", "echo AKIAIOSFODNN7EXAMPLE"},
		Args:    []string{"--token", "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"},
	}

	findings := ScanContainer(container)

	// We expect:
	// 1. EnvVar DATABASE_PASSWORD (Plaintext Sensitive Variable)
	// 2. EnvVar AWS_ACCESS_KEY_ID (AWS Access Key ID)
	// 3. Command command[2] (AWS Access Key ID)
	// 4. Arg arg[1] (GitHub Personal Access Token)
	
	expectedCount := 4
	if len(findings) != expectedCount {
		t.Fatalf("expected %d findings, got %d: %+v", expectedCount, len(findings), findings)
	}

	// Verify details
	foundPassword := false
	foundAWSKey := false
	foundCommandAWS := false
	foundArgToken := false

	for _, f := range findings {
		if f.Type == "EnvVar" && f.Name == "DATABASE_PASSWORD" && f.RuleName == "Plaintext Sensitive Variable" {
			foundPassword = true
		}
		if f.Type == "EnvVar" && f.Name == "AWS_ACCESS_KEY_ID" && f.RuleName == "AWS Access Key ID" {
			foundAWSKey = true
		}
		if f.Type == "Command" && f.RuleName == "AWS Access Key ID" {
			foundCommandAWS = true
		}
		if f.Type == "Arg" && f.RuleName == "GitHub Personal Access Token" {
			foundArgToken = true
		}
	}

	if !foundPassword {
		t.Error("failed to find DATABASE_PASSWORD exposure")
	}
	if !foundAWSKey {
		t.Error("failed to find AWS_ACCESS_KEY_ID exposure")
	}
	if !foundCommandAWS {
		t.Error("failed to find AWS key exposure in Command")
	}
	if !foundArgToken {
		t.Error("failed to find GitHub token in Args")
	}
}
