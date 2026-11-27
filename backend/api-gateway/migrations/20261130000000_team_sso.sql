-- Single sign-on and provisioning for teams.
--
-- A team proves it owns an email domain with a DNS TXT record. Only then can
-- its identity provider sign people in with addresses in that domain, or its
-- provisioning (SCIM) add them: otherwise a team could vouch for anyone's
-- address and take over their account.

CREATE TABLE IF NOT EXISTS team_domains (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(253) NOT NULL,          -- lowercased
    verify_code CHAR(32) NOT NULL,         -- goes in the TXT record
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, domain)
);
-- A domain belongs to at most one team once proven.
CREATE UNIQUE INDEX IF NOT EXISTS uq_team_domains_verified
    ON team_domains(domain) WHERE verified_at IS NOT NULL;

-- The team's OpenID Connect app, and its provisioning token.
CREATE TABLE IF NOT EXISTS team_sso (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    issuer VARCHAR(500),
    client_id VARCHAR(255),
    client_secret TEXT,                    -- sealed with the integration key
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    -- People with an address in the team's domains must use SSO (owners may
    -- still use a password, so a broken identity provider can't lock the team out).
    required BOOLEAN NOT NULL DEFAULT FALSE,
    -- Someone who signs in through SSO and isn't in the team yet joins with this role.
    join_role VARCHAR(16) NOT NULL DEFAULT 'member'
        CHECK (join_role IN ('admin', 'member', 'viewer')),
    scim_token_hash CHAR(64) UNIQUE,       -- SHA-256 of the provisioning token
    scim_token_hint VARCHAR(16),
    scim_token_created_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- People the team's identity provider provisioned. `id` in SCIM is the
-- Verdyx user id.
CREATE TABLE IF NOT EXISTS scim_users (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    external_id VARCHAR(255),
    user_name VARCHAR(255) NOT NULL,       -- lowercased address
    given_name VARCHAR(255),
    family_name VARCHAR(255),
    display_name VARCHAR(255),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scim_users_name ON scim_users(organization_id, user_name);
