package oap.authz

default decision := "deny"
default reason := "no matching OPA rule"

ticket_read if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "ticket.read"
  input.request.resource.type == "support.ticket"
}

bulk_export if {
  input.request.action.name == "customer.bulk_export"
}

decision := "allow_with_constraints" if {
  ticket_read
}

reason := "support agent may read tickets" if {
  ticket_read
}

policy_ids := ["opa/support-ticket-read"] if {
  ticket_read
}

constraints := {"readonly": true, "max_records": 25} if {
  ticket_read
}

decision := "deny" if {
  bulk_export
}

reason := "bulk export is prohibited" if {
  bulk_export
}

policy_ids := ["opa/no-bulk-export"] if {
  bulk_export
}
