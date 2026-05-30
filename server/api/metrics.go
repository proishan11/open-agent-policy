package api

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
)

type serverMetrics struct {
	startedAt time.Time

	authorizeRequests      atomic.Uint64
	authorizeInvalid       atomic.Uint64
	authorizeLatencyNanos  atomic.Uint64
	decisionAllow          atomic.Uint64
	decisionAllowConstrain atomic.Uint64
	decisionDeny           atomic.Uint64
	decisionApproval       atomic.Uint64
	decisionDelegation     atomic.Uint64
	decisionStepUp         atomic.Uint64
	decisionOther          atomic.Uint64

	auditWriteErrors atomic.Uint64
	auditQueryTotal  atomic.Uint64
	auditQueryErrors atomic.Uint64

	readinessChecks   atomic.Uint64
	readinessFailures atomic.Uint64
}

func newServerMetrics(now time.Time) *serverMetrics {
	return &serverMetrics{startedAt: now}
}

func (m *serverMetrics) recordAuthorize(duration time.Duration, decision string) {
	m.authorizeLatencyNanos.Add(uint64(duration))
	if decision == "" {
		return
	}
	switch decision {
	case model.DecisionAllow:
		m.decisionAllow.Add(1)
	case model.DecisionAllowConstrained:
		m.decisionAllowConstrain.Add(1)
	case model.DecisionDeny:
		m.decisionDeny.Add(1)
	case model.DecisionRequireApproval:
		m.decisionApproval.Add(1)
	case model.DecisionRequireDelegation:
		m.decisionDelegation.Add(1)
	case model.DecisionRequireStepUpAuth:
		m.decisionStepUp.Add(1)
	default:
		m.decisionOther.Add(1)
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := s.metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	uptime := time.Since(m.startedAt).Seconds()
	latencyCount := m.authorizeRequests.Load()
	latencySum := float64(m.authorizeLatencyNanos.Load()) / float64(time.Second)

	fmt.Fprintf(w, "# HELP oap_build_info OAP server build information.\n")
	fmt.Fprintf(w, "# TYPE oap_build_info gauge\n")
	fmt.Fprintf(w, "oap_build_info{version=\"v1alpha1\"} 1\n")
	fmt.Fprintf(w, "# HELP oap_uptime_seconds Seconds since this server process started.\n")
	fmt.Fprintf(w, "# TYPE oap_uptime_seconds gauge\n")
	fmt.Fprintf(w, "oap_uptime_seconds %.0f\n", uptime)
	fmt.Fprintf(w, "# HELP oap_authorize_requests_total Total authorization requests received.\n")
	fmt.Fprintf(w, "# TYPE oap_authorize_requests_total counter\n")
	fmt.Fprintf(w, "oap_authorize_requests_total %d\n", latencyCount)
	fmt.Fprintf(w, "# HELP oap_authorize_invalid_requests_total Total authorization requests rejected before evaluation.\n")
	fmt.Fprintf(w, "# TYPE oap_authorize_invalid_requests_total counter\n")
	fmt.Fprintf(w, "oap_authorize_invalid_requests_total %d\n", m.authorizeInvalid.Load())
	fmt.Fprintf(w, "# HELP oap_authorize_latency_seconds Authorization request latency.\n")
	fmt.Fprintf(w, "# TYPE oap_authorize_latency_seconds summary\n")
	fmt.Fprintf(w, "oap_authorize_latency_seconds_sum %.9f\n", latencySum)
	fmt.Fprintf(w, "oap_authorize_latency_seconds_count %d\n", latencyCount)
	fmt.Fprintf(w, "# HELP oap_authorization_decisions_total Authorization decisions by result.\n")
	fmt.Fprintf(w, "# TYPE oap_authorization_decisions_total counter\n")
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"allow\"} %d\n", m.decisionAllow.Load())
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"allow_with_constraints\"} %d\n", m.decisionAllowConstrain.Load())
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"deny\"} %d\n", m.decisionDeny.Load())
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"require_approval\"} %d\n", m.decisionApproval.Load())
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"require_delegation\"} %d\n", m.decisionDelegation.Load())
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"require_step_up_auth\"} %d\n", m.decisionStepUp.Load())
	fmt.Fprintf(w, "oap_authorization_decisions_total{decision=\"other\"} %d\n", m.decisionOther.Load())
	fmt.Fprintf(w, "# HELP oap_audit_write_errors_total Total failed audit writes.\n")
	fmt.Fprintf(w, "# TYPE oap_audit_write_errors_total counter\n")
	fmt.Fprintf(w, "oap_audit_write_errors_total %d\n", m.auditWriteErrors.Load())
	fmt.Fprintf(w, "# HELP oap_audit_query_requests_total Total audit query requests.\n")
	fmt.Fprintf(w, "# TYPE oap_audit_query_requests_total counter\n")
	fmt.Fprintf(w, "oap_audit_query_requests_total %d\n", m.auditQueryTotal.Load())
	fmt.Fprintf(w, "# HELP oap_audit_query_errors_total Total failed audit query requests.\n")
	fmt.Fprintf(w, "# TYPE oap_audit_query_errors_total counter\n")
	fmt.Fprintf(w, "oap_audit_query_errors_total %d\n", m.auditQueryErrors.Load())
	fmt.Fprintf(w, "# HELP oap_readiness_checks_total Total readiness checks.\n")
	fmt.Fprintf(w, "# TYPE oap_readiness_checks_total counter\n")
	fmt.Fprintf(w, "oap_readiness_checks_total %d\n", m.readinessChecks.Load())
	fmt.Fprintf(w, "# HELP oap_readiness_failures_total Total failed readiness checks.\n")
	fmt.Fprintf(w, "# TYPE oap_readiness_failures_total counter\n")
	fmt.Fprintf(w, "oap_readiness_failures_total %d\n", m.readinessFailures.Load())
}
