-- Teams (organisations): members with roles, email-bound invitations, scans
-- shared with a team, and API keys that belong to a team.
--
-- User ids are plain UUIDs owned by user-service (see 006), so members and
-- inviters carry no foreign key to `users`.

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- Only the SHA-256 of an invitation's link code is stored, like API keys.
CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL, -- stored lowercased
    role VARCHAR(16) NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    token_hash CHAR(64) NOT NULL UNIQUE,
    invited_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID
);
-- One open invitation per address per team; inviting again replaces it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_org_invitation_open
    ON organization_invitations(organization_id, email) WHERE accepted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_org_invitations_email
    ON organization_invitations(email) WHERE accepted_at IS NULL;

-- A scan saved to a team. Deleting the team hands its scans back to whoever
-- uploaded them.
ALTER TABLE submissions
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_submissions_org_created
    ON submissions(organization_id, created_at DESC) WHERE organization_id IS NOT NULL;

-- A team key: `user_id` is the admin who made it, `organization_id` the team
-- it acts for. Deleting the team deletes its keys.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(organization_id) WHERE organization_id IS NOT NULL;
