package scanner

import (
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Rule represents a secret detection rule with a name, regex, and description.
type Rule struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
}

// Finding represents a detected secret or exposure in a container.
type Finding struct {
	ContainerName string `json:"containerName"`
	Type          string `json:"type"`          // "EnvVar", "Command", "Arg"
	Name          string `json:"name"`          // Env var name or index
	RuleName      string `json:"ruleName"`      // Name of the rule triggered
	Description   string `json:"description"`   // Description of the vulnerability
	ValuePreview  string `json:"valuePreview"`  // Masked or preview value of the secret
}

var (
	// Standard rules for common secrets
	secretRules = []Rule{
		{
			Name:        "AWS Access Key ID",
			Description: "AWS Access Key ID detected",
			Regex:       regexp.MustCompile(`\b(AKIA|ASCA|ASIA)[0-9A-Z]{16}\b`),
		},
		{
			Name:        "AWS Secret Access Key",
			Description: "AWS Secret Access Key detected",
			Regex:       regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*[0-9a-zA-Z/+=]{40}`),
		},
		{
			Name:        "GitHub Personal Access Token",
			Description: "GitHub Personal Access Token detected",
			Regex:       regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b`),
		},
		{
			Name:        "Slack Webhook URL",
			Description: "Slack Webhook URL exposed in plaintext",
			Regex:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
		},
		{
			Name:        "Private Key",
			Description: "Private Key (RSA, PGP, SSH, etc.) detected",
			Regex:       regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
		},
		{
			Name:        "Generic Password/Token in URL",
			Description: "Connection string containing basic auth credentials",
			Regex:       regexp.MustCompile(`[a-zA-Z0-9]+://[^/\s:]+:[^/\s@]+@[^/\s]+`),
		},
	}

	// Keywords commonly associated with credentials
	sensitiveKeywords = []string{
		"PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "PASS", "AUTH", "API", "PWD", "SSH", "PRIVATE", "DATABASE_URL",
	}
)

// ScanString runs the regex-based rules against a given string.
func ScanString(val string) ([]Finding, bool) {
	var findings []Finding
	for _, rule := range secretRules {
		if rule.Regex.MatchString(val) {
			findings = append(findings, Finding{
				RuleName:     rule.Name,
				Description:  rule.Description,
				ValuePreview: previewValue(val),
			})
		}
	}
	return findings, len(findings) > 0
}

// ScanContainer scans a container spec (Env, Command, Args) for plaintext credentials.
func ScanContainer(container corev1.Container) []Finding {
	var findings []Finding

	// 1. Scan Environment Variables
	for _, env := range container.Env {
		// If the env var value is defined as a plain string
		if env.Value != "" {
			// A: Check for specific regex patterns
			if regexFindings, found := ScanString(env.Value); found {
				for _, rf := range regexFindings {
					rf.ContainerName = container.Name
					rf.Type = "EnvVar"
					rf.Name = env.Name
					findings = append(findings, rf)
				}
				continue
			}

			// B: Heuristics for sensitive variable names containing plaintext values
			if isSensitiveName(env.Name) {
				// Ignore placeholders, references (e.g. $(VAR)), and very short values
				if len(env.Value) > 4 && !strings.HasPrefix(env.Value, "$(") {
					findings = append(findings, Finding{
						ContainerName: container.Name,
						Type:          "EnvVar",
						Name:          env.Name,
						RuleName:      "Plaintext Sensitive Variable",
						Description:   fmt.Sprintf("Sensitive environment variable '%s' contains plaintext value. Use SecretReference instead.", env.Name),
						ValuePreview:  previewValue(env.Value),
					})
				}
			}
		}
	}

	// 2. Scan CLI Commands & Arguments
	for i, cmd := range container.Command {
		if regexFindings, found := ScanString(cmd); found {
			for _, rf := range regexFindings {
				rf.ContainerName = container.Name
				rf.Type = "Command"
				rf.Name = fmt.Sprintf("command[%d]", i)
				findings = append(findings, rf)
			}
		}
	}
	for i, arg := range container.Args {
		if regexFindings, found := ScanString(arg); found {
			for _, rf := range regexFindings {
				rf.ContainerName = container.Name
				rf.Type = "Arg"
				rf.Name = fmt.Sprintf("arg[%d]", i)
				findings = append(findings, rf)
			}
		}
	}

	return findings
}

// isSensitiveName checks if the environment variable name looks like a credential.
func isSensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

// previewValue masks the secret value to avoid logging it completely in plain text.
func previewValue(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	if len(val) <= 12 {
		return val[:2] + "****" + val[len(val)-2:]
	}
	return val[:4] + "****" + val[len(val)-4:]
}
