# Kubernetes ServiceAccount JWTs

Use `kubernetes_service_account` when the agent runs in Kubernetes and can use a
projected ServiceAccount token. These tokens are OIDC-compatible JWTs, so OAP
uses the same signature, issuer, expiry, audience, and subject validation path.

## Agent Binding

```yaml
apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: ticket-assistant
  namespace: support
spec:
  owner: group:support-platform
  type: chat_agent
  riskTier: medium
  capabilities:
    - ticket.read
  identityBindings:
    - type: kubernetes_service_account
      provider: kubernetes
      issuer: "https://kubernetes.default.svc"
      jwksUri: "https://kubernetes.default.svc/openid/v1/jwks"
      subject: "system:serviceaccount:support:ticket-assistant"
      audience: "oap-server"
```

Use your cluster's real issuer and JWKS URL. Managed clusters often expose an
external issuer URL instead of `https://kubernetes.default.svc`.

## Project The Token Into The Agent Pod

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ticket-assistant
  namespace: support
spec:
  template:
    spec:
      serviceAccountName: ticket-assistant
      containers:
        - name: agent
          image: registry.example.com/ticket-assistant:latest
          env:
            - name: OAP_SERVER_URL
              value: "https://oap.company.com"
            - name: OAP_TOKEN_FILE
              value: "/var/run/secrets/oap/token"
          volumeMounts:
            - name: oap-token
              mountPath: /var/run/secrets/oap
              readOnly: true
      volumes:
        - name: oap-token
          projected:
            sources:
              - serviceAccountToken:
                  audience: "oap-server"
                  expirationSeconds: 3600
                  path: token
```

## Create The Session

```python
from pathlib import Path

from open_agent_policy import OAPClient

runtime_token = Path("/var/run/secrets/oap/token").read_text().strip()

client = OAPClient(
    server_url="https://oap.company.com",
    agent_id="agent://support/ticket-assistant",
)
client.create_session(
    runtime_token=runtime_token,
    environment="production",
)
```

Subsequent `client.authorize(...)` calls use the OAP session token returned by
`create_session`.

## Operator Checklist

- Set a dedicated ServiceAccount per agent.
- Use projected tokens with a short expiration and OAP-specific audience.
- Configure OAP with an issuer/JWKS URL reachable from the OAP server.
- Rotate the pod when the agent identity or policy owner changes.
- Avoid using legacy long-lived ServiceAccount secret tokens.
