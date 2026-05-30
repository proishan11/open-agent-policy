package commands

import (
	"encoding/json"

	"gopkg.in/yaml.v3"
)

// yamlToJSON converts YAML bytes to JSON bytes.
// If the input is already valid JSON, it is returned as-is.
func yamlToJSON(data []byte) ([]byte, error) {
	// Try JSON first
	var js json.RawMessage
	if json.Unmarshal(data, &js) == nil {
		return data, nil
	}

	// Parse as YAML, then marshal to JSON
	var obj interface{}
	if err := yaml.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	// yaml.v3 produces map[string]interface{} already, which json.Marshal handles
	return json.Marshal(obj)
}
