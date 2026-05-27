package evaluator

import (
	"strconv"
	"strings"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// mergeConstraints combines constraints from multiple matching allow rules
// using "strictest wins" semantics:
//   - Numeric fields: minimum value wins (e.g., maxRecords 25 vs 100 → 25)
//   - Boolean fields: most restrictive wins (readonly=true wins over false)
//   - Array fields: union (e.g., redact fields are combined)
//
// Returns nil if no rules have constraints.
func mergeConstraints(matches []matchedRule) *model.Constraints {
	hasConstraints := false
	merged := &model.Constraints{}

	for _, m := range matches {
		if len(m.rule.Constraints) == 0 {
			continue
		}
		hasConstraints = true

		// maxRecords — minimum wins
		if v, ok := m.rule.Constraints["maxRecords"]; ok {
			maxRec := toInt(v)
			if maxRec > 0 {
				if merged.MaxRecords == nil || maxRec < *merged.MaxRecords {
					merged.MaxRecords = &maxRec
				}
			}
		}

		// readonly — true wins over false
		if v, ok := m.rule.Constraints["readonly"]; ok {
			if b, ok := v.(bool); ok && b {
				t := true
				merged.ReadOnly = &t
			} else if merged.ReadOnly == nil {
				f := false
				merged.ReadOnly = &f
			}
		}

		// redact — union of all fields
		if v, ok := m.rule.Constraints["redact"]; ok {
			if arr, ok := toStringSlice(v); ok {
				merged.RedactFields = unionStrings(merged.RedactFields, arr)
			}
		}

		// timeWindowSeconds — minimum wins
		if v, ok := m.rule.Constraints["timeWindowSeconds"]; ok {
			tw := toInt(v)
			if tw > 0 {
				if merged.TimeWindowSeconds == nil || tw < *merged.TimeWindowSeconds {
					merged.TimeWindowSeconds = &tw
				}
			}
		}
	}

	if !hasConstraints {
		return nil
	}
	return merged
}

// mergeObligations combines obligations from all matching allow rules.
// Audit is true if any rule requires it. Notify lists are unioned.
func mergeObligations(matches []matchedRule) *model.Obligations {
	hasObligations := false
	merged := &model.Obligations{}

	for _, m := range matches {
		if len(m.rule.Obligations) == 0 {
			continue
		}
		hasObligations = true

		if v, ok := m.rule.Obligations["audit"]; ok {
			if b, ok := v.(bool); ok && b {
				merged.Audit = true
			}
		}
		if v, ok := m.rule.Obligations["logFullRequest"]; ok {
			if b, ok := v.(bool); ok && b {
				merged.LogFullRequest = true
			}
		}
		if v, ok := m.rule.Obligations["notify"]; ok {
			if arr, ok := toStringSlice(v); ok {
				merged.Notify = unionStrings(merged.Notify, arr)
			}
		}
	}

	if !hasObligations {
		return nil
	}
	return merged
}

// parseDurationSeconds converts a human duration string like "30m", "1h", "24h"
// to seconds. Returns 0 if unparseable.
func parseDurationSeconds(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	// Try simple suffixed formats
	if strings.HasSuffix(s, "s") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
		if err == nil {
			return n
		}
	}
	if strings.HasSuffix(s, "m") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err == nil {
			return n * 60
		}
	}
	if strings.HasSuffix(s, "h") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err == nil {
			return n * 3600
		}
	}
	return 0
}

// toInt converts an interface{} to int, handling float64 (from JSON/YAML parsing)
// and int types.
func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// toStringSlice converts an interface{} (typically []interface{} from YAML) to []string.
func toStringSlice(v interface{}) ([]string, bool) {
	switch arr := v.(type) {
	case []string:
		return arr, true
	case []interface{}:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result, true
	default:
		return nil, false
	}
}

// unionStrings returns the union of two string slices (no duplicates).
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool)
	for _, s := range a {
		seen[s] = true
	}
	result := make([]string, len(a))
	copy(result, a)
	for _, s := range b {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	return result
}
