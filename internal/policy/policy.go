// Package policy authorizes every tool and projects the only data it may return.
// Its policy language is IAM-inspired, not AWS IAM compatible.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/krzysztof-gre/repbridge/internal/jsondoc"
)

const Version = "2026-10-20"

type Statement struct {
	Sid       string                         `json:"Sid,omitempty"`
	Effect    string                         `json:"Effect"`
	Action    []string                       `json:"Action"`
	Resource  string                         `json:"Resource"`
	Fields    []string                       `json:"Fields,omitempty"`
	Condition map[string]map[string][]string `json:"Condition,omitempty"`
}

type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Decision struct {
	Allowed bool     `json:"allowed"`
	Reason  string   `json:"reason"`
	Fields  []string `json:"fields,omitempty"`
}

func ConfiguredPath() string {
	if p := os.Getenv("REPBRIDGE_POLICY_FILE"); p != "" {
		return p
	}
	return "/etc/repbridge/policies/default.json"
}

func Load(path string) (*Policy, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 64<<10 {
		return nil, fmt.Errorf("policy must be a regular file of at most 64 KiB without group/world write permission")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open access policy")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("access policy changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read access policy")
	}
	return Parse(data)
}

func Parse(data []byte) (*Policy, error) {
	value, err := jsondoc.Decode(data, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("invalid access policy: %w", err)
	}
	root, ok := value.(map[string]any)
	if !ok || !keysAllowed(root, "Version", "Statement") {
		return nil, fmt.Errorf("invalid policy keys (case sensitive)")
	}
	if statements, ok := root["Statement"].([]any); ok {
		for _, v := range statements {
			s, ok := v.(map[string]any)
			if !ok || !keysAllowed(s, "Sid", "Effect", "Action", "Resource", "Fields", "Condition") {
				return nil, fmt.Errorf("invalid statement keys (case sensitive)")
			}
		}
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("invalid access policy")
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	var p Policy
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid access policy structure")
	}
	if p.Version != Version || p.Statement == nil || len(p.Statement) > 128 {
		return nil, fmt.Errorf("unsupported policy version or statement list")
	}
	for i, s := range p.Statement {
		if err := validate(s); err != nil {
			return nil, fmt.Errorf("policy statement %d: %w", i+1, err)
		}
	}
	return &p, nil
}

func validate(s Statement) error {
	if s.Effect != "Allow" && s.Effect != "Deny" {
		return fmt.Errorf("Effect must be Allow or Deny")
	}
	if s.Resource != "*" {
		return fmt.Errorf("only Resource=* is supported; account isolation is deployment-wide")
	}
	if len(s.Action) == 0 || len(s.Action) > 64 {
		return fmt.Errorf("Action must be a nonempty bounded list")
	}
	matched := []Action{}
	for _, pattern := range s.Action {
		found := false
		for _, a := range catalogue {
			if match(pattern, a.Name) {
				found = true
				matched = append(matched, a)
			}
		}
		if !found {
			return fmt.Errorf("Action pattern matches no supported action")
		}
	}
	if s.Effect == "Allow" && len(s.Fields) == 0 {
		return fmt.Errorf("Allow requires explicit Fields (use * only for deliberate full disclosure)")
	}
	if s.Effect == "Deny" && len(s.Fields) > 0 {
		return fmt.Errorf("Deny blocks actions; Fields is only valid for Allow")
	}
	if len(s.Fields) > 128 {
		return fmt.Errorf("too many field selections")
	}
	if s.Condition != nil && len(s.Condition) == 0 {
		return fmt.Errorf("empty Condition is ambiguous; omit it for an unconditional statement")
	}
	for _, path := range s.Fields {
		if _, err := fieldPath(path); err != nil {
			return err
		}
	}
	for op, keys := range s.Condition {
		if op != "StringEquals" && op != "StringLike" && !dateOperator(op) {
			return fmt.Errorf("unsupported condition operator")
		}
		if len(keys) == 0 {
			return fmt.Errorf("empty condition")
		}
		for key, values := range keys {
			if len(values) == 0 || len(values) > 32 {
				return fmt.Errorf("unsupported condition key or empty values")
			}
			for _, a := range matched {
				if dateOperator(op) {
					if key != ActivityStartTimeKey || !a.ActivityStartTime {
						return fmt.Errorf("date conditions require garmin:ActivityStartTime on supported activity reads")
					}
				} else if key != "garmin:WorkoutName" || !a.WorkoutName {
					return fmt.Errorf("string conditions require garmin:WorkoutName on supported workout operations")
				}
			}
			for _, v := range values {
				if v == "" || len(v) > 256 {
					return fmt.Errorf("condition values must be 1-256 bytes")
				}
				if dateOperator(op) {
					if _, err := parseDate(v); err != nil {
						return fmt.Errorf("date condition values must be RFC3339 timestamps with an explicit timezone")
					}
				}
			}
		}
	}
	return nil
}

// Possible is for discovery only. Invocation must call Evaluate with trusted attributes.
func (p *Policy) Possible(action string) bool {
	if _, known := actionsByName[action]; !known {
		return false
	}
	allowed := false
	for _, s := range p.Statement {
		if !matchesAction(s, action) {
			continue
		}
		if s.Effect == "Deny" && len(s.Condition) == 0 {
			return false
		}
		if s.Effect == "Allow" {
			allowed = true
		}
	}
	return allowed
}

func (p *Policy) NeedsWorkoutName(action string) bool {
	return p.needsAttribute(action, "garmin:WorkoutName")
}

func (p *Policy) NeedsActivityStartTime(action string) bool {
	return p.needsAttribute(action, ActivityStartTimeKey)
}

func (p *Policy) needsAttribute(action, key string) bool {
	for _, s := range p.Statement {
		if matchesAction(s, action) {
			for _, keys := range s.Condition {
				if _, found := keys[key]; found {
					return true
				}
			}
		}
	}
	return false
}

func (p *Policy) Evaluate(action string, attrs map[string]string) Decision {
	_, known := actionsByName[action]
	if !known {
		return Decision{Reason: "unknown_action"}
	}
	// Missing/malformed metadata must not bypass a date-based Deny through an
	// overlapping Allow. The runtime obtains this attribute from Garmin only.
	if p.NeedsActivityStartTime(action) {
		if _, err := parseDate(attrs[ActivityStartTimeKey]); err != nil {
			return Decision{Reason: "activity_start_time_required"}
		}
	}
	fields := map[string]bool{}
	allowed := false
	for _, s := range p.Statement {
		if !matchesAction(s, action) || !conditionsMatch(s.Condition, attrs) {
			continue
		}
		if s.Effect == "Deny" {
			return Decision{Reason: "explicit_deny"}
		}
		allowed = true
		for _, f := range s.Fields {
			fields[f] = true
		}
	}
	if !allowed {
		return Decision{Reason: "implicit_deny"}
	}
	d := Decision{Allowed: true, Reason: "allowed", Fields: []string{}}
	for f := range fields {
		d.Fields = append(d.Fields, f)
	}
	sort.Strings(d.Fields)
	return d
}

func matchesAction(s Statement, action string) bool {
	for _, pattern := range s.Action {
		if match(pattern, action) {
			return true
		}
	}
	return false
}

func conditionsMatch(conditions map[string]map[string][]string, attrs map[string]string) bool {
	for op, keys := range conditions {
		for key, values := range keys {
			actual, present := attrs[key]
			if !present {
				return false
			}
			if dateOperator(op) {
				if !dateMatches(op, actual, values) {
					return false
				}
				continue
			}
			ok := false
			for _, v := range values {
				if (op == "StringEquals" && v == actual) || (op == "StringLike" && match(v, actual)) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
	}
	return true
}

// Anchored rune-aware glob matching. Only * and ? are special; regexp
// metacharacters and path separators remain literal, and ? matches newlines.
func match(pattern, value string) bool {
	if len(pattern) > 256 {
		return false
	}
	if !strings.ContainsAny(pattern, "*?") && utf8.ValidString(pattern) && utf8.ValidString(value) {
		return pattern == value
	}
	p, v := []rune(pattern), []rune(value)
	pi, vi, star, retry := 0, 0, -1, 0
	for vi < len(v) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] != '*' && p[pi] == v[vi]):
			pi++
			vi++
		case pi < len(p) && p[pi] == '*':
			star = pi
			pi++
			retry = vi
		case star >= 0:
			pi = star + 1
			retry++
			vi = retry
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func keysAllowed(value map[string]any, keys ...string) bool {
	for k := range value {
		ok := false
		for _, allowed := range keys {
			if k == allowed {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
