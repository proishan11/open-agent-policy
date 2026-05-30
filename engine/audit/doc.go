// Package audit provides structured audit event sinks for OAP.
//
// Every authorization decision produces an audit event. The audit package
// defines the Sink interface and provides concrete implementations.
//
// Implementations:
//   - JSONLSink: writes one JSON line per event to a file (for dev/testing)
//   - StdoutSink: writes events to stdout (for containerized deployments)
//   - MemorySink: holds events in memory (for testing)
//   - MultiSink: fans out writes to multiple sinks
//
// Durable queryable sinks implement Querier. The Postgres audit sink lives in
// engine/store/postgres so it can share the server's connection pool.
//
// The audit sink is called by the server after every evaluation. It is NOT
// called by the evaluator directly — this keeps the evaluator pure (no I/O).
//
// Data flow:
//
//	Evaluator returns Decision
//	  → Server builds AuditEvent from Request + Decision
//	  → Server calls Sink.Write(event)
//	  → Sink persists the event
package audit
