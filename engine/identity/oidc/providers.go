package oidc

import (
	"fmt"
	"strings"
)

// ForKeycloak creates a Verifier configured for a Keycloak realm.
// issuerURL is like "https://keycloak.corp.com/realms/main".
func ForKeycloak(issuerURL, audience string) (*Verifier, error) {
	return NewVerifier(Config{
		Issuer:   issuerURL,
		Audience: audience,
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "groups",
			RolesClaim:   "realm_access.roles",
		},
	})
}

// ForOkta creates a Verifier configured for an Okta org.
// orgURL is like "https://company.okta.com" or a custom authorization server
// like "https://company.okta.com/oauth2/default".
func ForOkta(orgURL, audience string) (*Verifier, error) {
	return NewVerifier(Config{
		Issuer:   orgURL,
		Audience: audience,
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "groups",
			RolesClaim:   "roles",
		},
	})
}

// ForAzureAD creates a Verifier configured for Azure AD / Entra ID.
// tenantID is the Azure AD tenant GUID. Use "common" for multi-tenant.
func ForAzureAD(tenantID, audience string) (*Verifier, error) {
	issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
	return NewVerifier(Config{
		Issuer:   issuer,
		Audience: audience,
		JWKSUrl:  fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID),
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "preferred_username",
			GroupsClaim:  "groups",
			RolesClaim:   "roles",
		},
	})
}

// ForGoogle creates a Verifier configured for Google Workspace / Google Cloud.
// hostedDomain restricts to a specific Google Workspace domain (e.g., "company.com").
// Pass "" to allow any Google account.
func ForGoogle(audience, hostedDomain string) (*Verifier, error) {
	cfg := Config{
		Issuer:   "https://accounts.google.com",
		Audience: audience,
		JWKSUrl:  "https://www.googleapis.com/oauth2/v3/certs",
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "groups",
		},
	}
	if hostedDomain != "" {
		cfg.RequiredClaims = map[string]string{"hd": hostedDomain}
	}
	return NewVerifier(cfg)
}

// ForCognito creates a Verifier configured for AWS Cognito User Pools.
// region is the AWS region (e.g., "us-east-1"), poolID is the user pool ID.
func ForCognito(region, poolID, audience string) (*Verifier, error) {
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, poolID)
	return NewVerifier(Config{
		Issuer:   issuer,
		Audience: audience,
		JWKSUrl:  issuer + "/.well-known/jwks.json",
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "cognito:groups",
		},
	})
}

// ForAuth0 creates a Verifier configured for Auth0.
// domain is like "company.auth0.com" or a custom domain.
func ForAuth0(domain, audience string) (*Verifier, error) {
	if !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}
	issuer := strings.TrimSuffix(domain, "/") + "/"
	return NewVerifier(Config{
		Issuer:   issuer,
		Audience: audience,
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "groups",
			RolesClaim:   "permissions",
		},
	})
}

// ForPingIdentity creates a Verifier configured for PingIdentity / PingFederate.
// issuerURL is the PingFederate OIDC issuer.
func ForPingIdentity(issuerURL, audience string) (*Verifier, error) {
	return NewVerifier(Config{
		Issuer:   issuerURL,
		Audience: audience,
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "groups",
		},
	})
}

// ForOneLogin creates a Verifier configured for OneLogin.
func ForOneLogin(issuerURL, audience string) (*Verifier, error) {
	return NewVerifier(Config{
		Issuer:   issuerURL,
		Audience: audience,
		ClaimMappings: ClaimMappings{
			SubjectClaim: "sub",
			EmailClaim:   "email",
			GroupsClaim:  "groups",
			RolesClaim:   "roles",
		},
	})
}

// ForGenericOIDC creates a Verifier for any OIDC-compliant provider.
// This is the escape hatch for providers without a dedicated helper.
func ForGenericOIDC(issuerURL, audience string, claimMappings *ClaimMappings) (*Verifier, error) {
	cfg := Config{
		Issuer:   issuerURL,
		Audience: audience,
	}
	if claimMappings != nil {
		cfg.ClaimMappings = *claimMappings
	}
	return NewVerifier(cfg)
}
