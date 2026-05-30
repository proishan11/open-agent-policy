package evaluator

import (
	"fmt"
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
	allowedFieldsSet := false

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

		// allowedFields — intersection wins because it is the narrowest field set.
		if v, ok := m.rule.Constraints["allowedFields"]; ok {
			if arr, ok := toStringSlice(v); ok {
				if !allowedFieldsSet {
					fields := cloneStrings(arr)
					merged.AllowedFields = &fields
					allowedFieldsSet = true
				} else if merged.AllowedFields != nil {
					fields := intersectStrings(*merged.AllowedFields, arr)
					merged.AllowedFields = &fields
				}
			}
		}

		// expiresIn — minimum duration wins.
		if v, ok := m.rule.Constraints["expiresIn"]; ok {
			if s, ok := v.(string); ok {
				seconds := parseDurationSeconds(s)
				if seconds > 0 {
					if merged.ExpiresInSeconds == nil || seconds < *merged.ExpiresInSeconds {
						merged.ExpiresInSeconds = &seconds
					}
				}
			}
		}
	}

	if !hasConstraints {
		return nil
	}
	return merged
}

// validateConstraints rejects policy constraint keys the evaluator cannot enforce.
// Silently dropping a constraint turns a narrow allow into a broad allow, so this
// is intentionally fail-closed.
func validateConstraints(constraints map[string]interface{}) error {
	for key, value := range constraints {
		switch key {
		case "readonly":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("constraint %q must be boolean", key)
			}
		case "maxRecords", "timeWindowSeconds":
			if toInt(value) <= 0 {
				return fmt.Errorf("constraint %q must be a positive integer", key)
			}
		case "redact", "allowedFields":
			fields, ok := toStringSlice(value)
			if !ok || len(fields) == 0 {
				return fmt.Errorf("constraint %q must be a non-empty string array", key)
			}
		case "expiresIn":
			duration, ok := value.(string)
			if !ok || parseDurationSeconds(duration) <= 0 {
				return fmt.Errorf("constraint %q must be a duration such as 15m, 1h, or 24h", key)
			}
		default:
			return fmt.Errorf("unsupported constraint %q", key)
		}
	}
	return nil
}

// constraintsFromBackendMap maps backend-native JSON constraint names into the
// typed decision model. Unknown keys fail closed because silently dropping a
// constraint can widen an allow.
func constraintsFromBackendMap(constraints map[string]interface{}) (*model.Constraints, error) {
	if len(constraints) == 0 {
		return nil, nil
	}

	result := &model.Constraints{}
	allowedFieldsSet := false
	hasConstraints := false

	for key, value := range constraints {
		switch key {
		case "maxRecords", "max_records":
			maxRecords := toInt(value)
			if maxRecords <= 0 {
				return nil, fmt.Errorf("constraint %q must be a positive integer", key)
			}
			if result.MaxRecords == nil || maxRecords < *result.MaxRecords {
				result.MaxRecords = &maxRecords
			}
			hasConstraints = true
		case "readonly", "readOnly", "read_only":
			readonly, ok := value.(bool)
			if !ok {
				return nil, fmt.Errorf("constraint %q must be boolean", key)
			}
			if readonly {
				t := true
				result.ReadOnly = &t
			} else if result.ReadOnly == nil {
				f := false
				result.ReadOnly = &f
			}
			hasConstraints = true
		case "redact", "redactFields", "redact_fields":
			fields, ok := toStringSlice(value)
			if !ok || len(fields) == 0 {
				return nil, fmt.Errorf("constraint %q must be a non-empty string array", key)
			}
			result.RedactFields = unionStrings(result.RedactFields, fields)
			hasConstraints = true
		case "timeWindowSeconds", "time_window_seconds":
			timeWindowSeconds := toInt(value)
			if timeWindowSeconds <= 0 {
				return nil, fmt.Errorf("constraint %q must be a positive integer", key)
			}
			if result.TimeWindowSeconds == nil || timeWindowSeconds < *result.TimeWindowSeconds {
				result.TimeWindowSeconds = &timeWindowSeconds
			}
			hasConstraints = true
		case "allowedFields", "allowed_fields":
			fields, ok := toStringSlice(value)
			if !ok || len(fields) == 0 {
				return nil, fmt.Errorf("constraint %q must be a non-empty string array", key)
			}
			if !allowedFieldsSet {
				cloned := cloneStrings(fields)
				result.AllowedFields = &cloned
				allowedFieldsSet = true
			} else if result.AllowedFields != nil {
				intersected := intersectStrings(*result.AllowedFields, fields)
				result.AllowedFields = &intersected
			}
			hasConstraints = true
		case "expiresIn":
			duration, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("constraint %q must be a duration such as 15m, 1h, or 24h", key)
			}
			seconds := parseDurationSeconds(duration)
			if seconds <= 0 {
				return nil, fmt.Errorf("constraint %q must be a duration such as 15m, 1h, or 24h", key)
			}
			if result.ExpiresInSeconds == nil || seconds < *result.ExpiresInSeconds {
				result.ExpiresInSeconds = &seconds
			}
			hasConstraints = true
		case "expiresInSeconds", "expires_in_seconds":
			seconds := toInt(value)
			if seconds <= 0 {
				return nil, fmt.Errorf("constraint %q must be a positive integer", key)
			}
			if result.ExpiresInSeconds == nil || seconds < *result.ExpiresInSeconds {
				result.ExpiresInSeconds = &seconds
			}
			hasConstraints = true
		default:
			return nil, fmt.Errorf("unsupported constraint %q", key)
		}
	}

	if !hasConstraints {
		return nil, nil
	}
	return result, nil
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

// validateObligations rejects obligation keys the evaluator/enforcement layer
// does not currently understand.
func validateObligations(obligations map[string]interface{}) error {
	for key, value := range obligations {
		switch key {
		case "audit", "logFullRequest":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("obligation %q must be boolean", key)
			}
		case "notify":
			notify, ok := toStringSlice(value)
			if !ok || len(notify) == 0 {
				return fmt.Errorf("obligation %q must be a non-empty string array", key)
			}
		default:
			return fmt.Errorf("unsupported obligation %q", key)
		}
	}
	return nil
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
			} else {
				return nil, false
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

func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func intersectStrings(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var result []string
	seen := make(map[string]bool)
	for _, s := range a {
		if inB[s] && !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	return result
}
