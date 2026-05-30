package model

import "time"

// AgentState constants define the lifecycle states of an agent.
const (
	AgentStateActive        = "active"
	AgentStateSuspended     = "suspended"
	AgentStateRevoked       = "revoked"
	AgentStatePendingReview = "pending_review"
)

// Agent represents a registered autonomous software actor in OAP.
// Registration is mandatory — unregistered agents are always denied.
//
// This maps to spec/v1alpha1/agent.schema.json.
type Agent struct {
	APIVersion string      `json:"apiVersion" yaml:"apiVersion"`
	Kind       string      `json:"kind" yaml:"kind"`
	Metadata   Metadata    `json:"metadata" yaml:"metadata"`
	Spec       AgentSpec   `json:"spec" yaml:"spec"`
	Status     AgentStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// AgentSpec defines the agent's properties and capabilities.
type AgentSpec struct {
	// Owner is the team or individual responsible for this agent.
	Owner string `json:"owner" yaml:"owner"`

	// Description is a human-readable summary of what the agent does.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Type categorizes the agent's behavior model.
	// One of: "workflow_agent", "chat_agent", "autonomous_agent", "pipeline_agent", "tool_agent".
	Type string `json:"type" yaml:"type"`

	// Version is the declared version of the agent software.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`

	// Lifecycle stage of the agent.
	// One of: "development", "staging", "production", "deprecated".
	Lifecycle string `json:"lifecycle,omitempty" yaml:"lifecycle,omitempty"`

	// RiskTier is the assessed risk level.
	// One of: "low", "medium", "high", "critical".
	RiskTier string `json:"riskTier" yaml:"riskTier"`

	// Publisher identifies the organization that publishes this agent.
	Publisher string `json:"publisher,omitempty" yaml:"publisher,omitempty"`

	// Framework is the agent framework used (e.g., "langchain", "crewai").
	Framework string `json:"framework,omitempty" yaml:"framework,omitempty"`

	// Capabilities lists what the agent can do at a high level.
	Capabilities []string `json:"capabilities" yaml:"capabilities"`

	// WorkloadIdentity records the standards-compatible workload identity
	// associated with this logical agent, such as a SPIFFE ID.
	WorkloadIdentity *WorkloadIdentityProfile `json:"workloadIdentity,omitempty" yaml:"workloadIdentity,omitempty"`

	// IdentityBindings maps verifiable runtime identities to this agent.
	// OAP checks the runtime token's issuer+subject against these bindings
	// to cryptographically prove which agent a workload is.
	IdentityBindings []IdentityBinding `json:"identityBindings,omitempty" yaml:"identityBindings,omitempty"`

	// Runtime describes the agent's deployment context.
	Runtime *AgentRuntime `json:"runtime,omitempty" yaml:"runtime,omitempty"`

	// Tools lists the tools this agent declares it uses,
	// with the action and resource each tool maps to.
	Tools []AgentToolBinding `json:"tools,omitempty" yaml:"tools,omitempty"`
}

// WorkloadIdentityProfile records the standards-compatible workload identity
// for an OAP agent. The logical OAP ID remains agent://<namespace>/<name>;
// this profile maps it to a deployment identity such as a SPIFFE ID.
type WorkloadIdentityProfile struct {
	// ID is the stable workload identifier URI, preferably a SPIFFE ID.
	ID string `json:"id" yaml:"id"`

	// Type identifies the workload identity profile.
	// One of: "spiffe", "wimse", "custom_uri".
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	// TrustDomain identifies the issuing or governing trust domain.
	TrustDomain string `json:"trustDomain,omitempty" yaml:"trustDomain,omitempty"`

	// AttestationLevel records the assurance level behind this identity.
	// One of: "none", "platform", "hardware", "supply_chain".
	AttestationLevel string `json:"attestationLevel,omitempty" yaml:"attestationLevel,omitempty"`
}

// IdentityBinding maps a verifiable runtime identity to this agent.
// When an agent workload presents a token, OAP verifies the token's
// issuer and subject match a registered binding before trusting the identity.
type IdentityBinding struct {
	// Type is the identity mechanism.
	// One of: "oidc_client", "kubernetes_service_account", "spiffe", "wimse".
	Type string `json:"type" yaml:"type"`

	// Provider is a human-readable name (e.g., "keycloak", "okta", "azure-ad").
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`

	// Issuer is the expected token issuer URL.
	Issuer string `json:"issuer" yaml:"issuer"`

	// JWKSURI is an explicit key set or SPIFFE bundle endpoint.
	// Use this when the issuer does not expose OIDC discovery.
	JWKSURI string `json:"jwksUri,omitempty" yaml:"jwksUri,omitempty"`

	// Subject is the expected token subject or authorized party.
	// For OIDC client_credentials: the client_id or azp claim.
	// For K8s: "system:serviceaccount:<ns>:<name>".
	// For SPIFFE/WIMSE: the workload identifier URI in the sub claim.
	Subject string `json:"subject" yaml:"subject"`

	// Audience is the expected audience claim (optional).
	Audience string `json:"audience,omitempty" yaml:"audience,omitempty"`
}

// AgentRuntime describes the agent's deployment environment.
type AgentRuntime struct {
	Platform         string `json:"platform,omitempty" yaml:"platform,omitempty"`
	Namespace        string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	ServiceAccount   string `json:"serviceAccount,omitempty" yaml:"serviceAccount,omitempty"`
	WorkloadIdentity string `json:"workloadIdentity,omitempty" yaml:"workloadIdentity,omitempty"`
	ImageDigest      string `json:"imageDigest,omitempty" yaml:"imageDigest,omitempty"`
}

// AgentToolBinding maps a tool name to an action and resource pattern.
type AgentToolBinding struct {
	Name     string             `json:"name" yaml:"name"`
	Action   string             `json:"action" yaml:"action"`
	Resource *AgentToolResource `json:"resource,omitempty" yaml:"resource,omitempty"`
}

// AgentToolResource specifies what resource type a tool operates on
// and how to extract the resource ID from tool input.
type AgentToolResource struct {
	Type   string `json:"type,omitempty" yaml:"type,omitempty"`
	IDFrom string `json:"idFrom,omitempty" yaml:"idFrom,omitempty"`
}

// AgentStatus tracks the current runtime state of an agent.
type AgentStatus struct {
	State        string    `json:"state,omitempty" yaml:"state,omitempty"`
	RegisteredAt time.Time `json:"registeredAt,omitempty" yaml:"registeredAt,omitempty"`
	LastSeenAt   time.Time `json:"lastSeenAt,omitempty" yaml:"lastSeenAt,omitempty"`
}

// ID returns the canonical agent URI: "agent://<namespace>/<name>".
func (a *Agent) ID() string {
	return "agent://" + a.Metadata.Namespace + "/" + a.Metadata.Name
}

// IsActive returns true if the agent is in an active state.
func (a *Agent) IsActive() bool {
	return a.Status.State == AgentStateActive || a.Status.State == ""
}
