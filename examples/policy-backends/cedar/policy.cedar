permit(
  principal == OAP::Agent::"agent://support/ticket-assistant",
  action == OAP::Action::"ticket.read",
  resource
);

forbid(
  principal == OAP::Agent::"agent://support/ticket-assistant",
  action == OAP::Action::"customer.bulk_export",
  resource
);

