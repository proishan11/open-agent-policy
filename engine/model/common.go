package model

// Metadata is the standard metadata block shared across all OAP resources.
// It follows the Kubernetes-style metadata pattern (name, namespace, labels, annotations).
type Metadata struct {
	// Name uniquely identifies the resource within its namespace.
	Name string `json:"name" yaml:"name"`

	// Namespace is the organizational scope (e.g., "finance", "engineering").
	Namespace string `json:"namespace" yaml:"namespace"`

	// Labels are key-value pairs used for selection and filtering.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Annotations hold non-identifying metadata (e.g., description, docs URL).
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// ResourceRef is a lightweight resource reference used in authorization requests.
// It identifies a resource by type and ID without carrying the full registration data.
type ResourceRef struct {
	// Type is the resource type (e.g., "erp.invoice", "database.users").
	Type string `json:"type" yaml:"type"`

	// ID is the specific resource instance identifier (e.g., "INV-001").
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// Classification is the data sensitivity level (if known at request time).
	Classification string `json:"classification,omitempty" yaml:"classification,omitempty"`
}

// Resource represents a registered resource type in OAP.
// Resources are what agents act upon (databases, APIs, files, SaaS endpoints).
//
// This maps to spec/v1alpha1/resource.schema.json.
type Resource struct {
	APIVersion string       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string       `json:"kind" yaml:"kind"`
	Metadata   Metadata     `json:"metadata" yaml:"metadata"`
	Spec       ResourceSpec `json:"spec" yaml:"spec"`
}

// ResourceSpec defines the resource's properties.
type ResourceSpec struct {
	// Type categorizes the resource (e.g., "database", "api", "file").
	Type string `json:"type" yaml:"type"`

	// Description is a human-readable summary.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Owner is the team or individual responsible for this resource.
	Owner string `json:"owner" yaml:"owner"`

	// Classification is the data sensitivity level.
	// One of: "public", "internal", "confidential", "restricted".
	Classification string `json:"classification,omitempty" yaml:"classification,omitempty"`

	// Environment where this resource lives.
	// One of: "development", "staging", "production".
	Environment string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// Actions lists the valid actions on this resource type.
	Actions []string `json:"actions,omitempty" yaml:"actions,omitempty"`

	// Attributes are arbitrary key-value metadata about the resource.
	Attributes map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Tool represents a registered tool in OAP.
// Tools are the mechanisms agents use to perform actions on resources
// (MCP tools, HTTP endpoints, Python functions, shell commands).
//
// This maps to spec/v1alpha1/tool.schema.json.
type Tool struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       ToolSpec `json:"spec" yaml:"spec"`
}

// ToolSpec defines the tool's properties.
type ToolSpec struct {
	// Name is the tool's identifier as seen by the agent.
	Name string `json:"name" yaml:"name"`

	// Description is a human-readable summary.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Action is the canonical action this tool performs (e.g., "erp.invoice.read").
	Action string `json:"action" yaml:"action"`

	// Protocol is how the tool is invoked.
	// One of: "mcp", "http", "function", "shell", "sdk".
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Server identifies the hosting endpoint (e.g., MCP server name).
	Server string `json:"server,omitempty" yaml:"server,omitempty"`

	// Risk is the assessed risk level of this tool.
	Risk string `json:"risk,omitempty" yaml:"risk,omitempty"`

	// Resource describes what resource type this tool acts on.
	Resource *AgentToolResource `json:"resource,omitempty" yaml:"resource,omitempty"`

	// InputSchema is the JSON Schema for the tool's input parameters.
	InputSchema map[string]interface{} `json:"inputSchema,omitempty" yaml:"inputSchema,omitempty"`
}
