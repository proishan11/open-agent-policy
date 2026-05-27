// Package grant implements JWT-based short-lived grant issuance for OAP.
//
// When the evaluator returns allow or allow_with_constraints, the server
// issues a signed JWT grant that the enforcement point (gateway, proxy, or
// resource) can verify independently.
//
// Grants encode:
//   - Agent ID, action, resource scope
//   - Constraints (readonly, redact fields, max records)
//   - Expiry (typically 15 minutes)
//   - Issuer (the OAP server)
//
// Data flow:
//
//	Evaluator returns allow → GrantIssuer.Issue(decision) → signed JWT
//	Enforcement point receives JWT → GrantVerifier.Verify(token) → claims
//	Claims include constraints the enforcement point must apply
package grant
