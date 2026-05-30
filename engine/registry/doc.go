// Package registry provides in-memory registries for agents, resources, tools,
// and policies. Registries can be populated from YAML/JSON files on disk or
// programmatically via the API.
//
// The registry is the source of truth for what agents exist and what policies
// govern them. The evaluator queries the registry before evaluating any request.
//
// Key types:
//   - Store: the top-level registry holding all four sub-registries
//   - AgentRegistry: tracks registered agents and their status
//   - PolicyRegistry: tracks policies and provides matching
//   - ResourceRegistry: tracks resource types
//   - ToolRegistry: tracks tool registrations
//
// Data flow:
//
//	Files on disk (YAML/JSON)
//	  → Store.LoadDir(path)
//	    → parses by "kind" field → routes to correct sub-registry
//	  → Evaluator queries Store during authorization
//
// For production, the registry is synced from the control plane via the
// bundle API. For development, loading from local files is sufficient.
package registry
