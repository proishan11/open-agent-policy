package oap.authz

default decision := "deny"
default reason := "no matching OPA rule"
default policy_ids := []
default constraints := {}
default approval := null

ticket_read if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "ticket.read"
  input.request.resource.type == "support.ticket"
}

customer_read if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "customer.read"
  input.request.resource.type == "crm.customer"
}

internal_message if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "message.send"
  input.request.resource.type == "slack.channel"
  input.request.resource.owner == "channel:internal"
}

external_message if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "message.send"
  input.request.resource.type == "slack.channel"
  input.request.resource.owner == "channel:external"
}

escalation_create if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "escalation.issue.create"
  input.request.resource.type == "support.ticket"
}

ticket_update_allowed if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "ticket.update"
  input.request.resource.type == "support.ticket"
  input.request.resource.id != "T-200"
}

ticket_update_denied if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "ticket.update"
  input.request.resource.type == "support.ticket"
  input.request.resource.id == "T-200"
}

bulk_export if {
  input.request.action.name in {"ticket.bulk_export", "customer.bulk_export"}
}

administrative_or_destructive if {
  input.request.action.name in {"customer.delete", "policy.modify", "repository.settings.modify", "ticket.delete"}
}

decision := "allow_with_constraints" if {
  ticket_read
}

reason := "OPA: support agent may read tickets with readonly limits" if {
  ticket_read
}

policy_ids := ["opa/support-ticket-read"] if {
  ticket_read
}

constraints := {"readonly": true, "max_records": 25} if {
  ticket_read
}

decision := "allow_with_constraints" if {
  customer_read
}

reason := "OPA: support agent may read customer records with redaction" if {
  customer_read
}

policy_ids := ["opa/customer-read-redacted"] if {
  customer_read
}

constraints := {"redact_fields": ["tax_identifier", "billing_account", "bank_account"]} if {
  customer_read
}

decision := "allow" if {
  internal_message
}

reason := "OPA: internal support channel message allowed" if {
  internal_message
}

policy_ids := ["opa/internal-message-send"] if {
  internal_message
}

decision := "require_approval" if {
  external_message
}

reason := "OPA: external customer updates require support manager approval" if {
  external_message
}

policy_ids := ["opa/external-message-approval"] if {
  external_message
}

approval := {"approvers": ["group:support-managers"], "expires_in_seconds": 1800} if {
  external_message
}

decision := "allow" if {
  escalation_create
}

reason := "OPA: escalation issue creation allowed" if {
  escalation_create
}

policy_ids := ["opa/escalation-create"] if {
  escalation_create
}

decision := "allow_with_constraints" if {
  ticket_update_allowed
}

reason := "OPA: ticket update allowed for mutable workflow fields" if {
  ticket_update_allowed
}

policy_ids := ["opa/ticket-update-fields"] if {
  ticket_update_allowed
}

constraints := {"allowed_fields": ["status", "priority", "assignee"]} if {
  ticket_update_allowed
}

decision := "deny" if {
  ticket_update_denied
}

reason := "OPA: T-200 is locked for update in this validation profile" if {
  ticket_update_denied
}

policy_ids := ["opa/ticket-update-locked-ticket"] if {
  ticket_update_denied
}

decision := "deny" if {
  bulk_export
}

reason := "OPA: bulk export is prohibited" if {
  bulk_export
}

policy_ids := ["opa/no-bulk-export"] if {
  bulk_export
}

decision := "deny" if {
  administrative_or_destructive
}

reason := "OPA: destructive or administrative actions are prohibited" if {
  administrative_or_destructive
}

policy_ids := ["opa/no-destructive-admin-actions"] if {
  administrative_or_destructive
}
