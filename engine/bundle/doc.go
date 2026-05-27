// Package bundle implements policy bundle sync for embedded evaluators.
//
// Embedded evaluators (in SDKs, gateways, and proxies) need local copies
// of agents and policies. The bundle package provides:
//
//   - Bundle format: a JSON manifest listing agents and policies
//   - BundleServer: serves bundles from the control plane registry
//   - BundleClient: polls the server and updates the local store
//
// Sync interval is configurable. The client uses ETags to avoid
// re-downloading unchanged bundles.
//
// Data flow:
//
//	OAP Server (control plane)
//	  └── BundleServer → GET /v1/bundles → JSON bundle
//
//	Embedded evaluator
//	  └── BundleClient → polls /v1/bundles → updates local Store
package bundle
