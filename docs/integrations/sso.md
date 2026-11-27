# Single sign-on and provisioning

A team can let its people sign in to Verdyx with the company's own identity
provider, and have that provider add and remove them automatically:

- **Single sign-on (SSO)** uses OpenID Connect. It works with Okta,
  Microsoft Entra ID, Google Workspace, Auth0, Keycloak, OneLogin and any
  other OpenID Connect provider.
- **Provisioning** uses SCIM 2.0. When someone is assigned the Verdyx app,
  they're added to the team. When they're unassigned or leave the company,
  they're removed from it.

Team owners and admins set both up on the team's **Sign-in** tab, at
[verdyx.dev/teams](https://verdyx.dev/teams).

## 1. Prove your email domain

Add each domain your people sign in with, such as `example.com`. Verdyx shows
a TXT record to add at your DNS provider:

| Type | Name | Value |
|---|---|---|
| TXT | `_verdyx-challenge.example.com` | `verdyx-domain-verification=…` |

Then press **Verify**. DNS changes can take a few minutes to appear. You can
remove the record once the domain is verified.

**Why this step is needed:** Verdyx signs people in to the account with the
address the identity provider vouches for. Only addresses in your verified
domains are accepted, so another team's identity provider can't vouch for
your people, and yours can't vouch for anyone else. A domain can belong to
only one team. Subdomains count only if you add and verify them too.

## 2. Connect your identity provider

The **Sign-in** tab shows the redirect URI to give your provider:

```
https://verdyx.dev/api/v1/auth/sso/callback
```

Create the app in your provider (see below), then enter its **issuer URL**,
**client ID** and **client secret**. The secret is stored encrypted and is
never shown again.

### Okta

1. **Applications → Applications → Create App Integration**. Choose
   **OIDC - OpenID Connect** and **Web Application**.
2. Under **Sign-in redirect URIs**, enter the redirect URI above. Leave
   **Authorization Code** as the grant type.
3. Under **Assignments**, choose who may use Verdyx.
4. On the app's **General** tab, copy the **Client ID** and **Client secret**.
5. The issuer URL is your Okta domain, for example
   `https://example.okta.com`. If you use a custom authorization server,
   use its issuer instead, for example `https://example.okta.com/oauth2/default`.

### Microsoft Entra ID

1. **Entra admin center → Applications → App registrations → New
   registration**. Under **Redirect URI**, choose **Web** and enter the
   redirect URI above.
2. On **Certificates & secrets**, make a **New client secret** and copy its
   **Value**.
3. On **Token configuration**, **Add optional claim** → **ID** → `email`.
   Without it, Verdyx uses the person's sign-in name (`preferred_username`),
   which is usually their address too.
4. On **Overview**, copy the **Application (client) ID** and the **Directory
   (tenant) ID**.
5. The issuer URL is `https://login.microsoftonline.com/<tenant ID>/v2.0`.

To choose who may sign in, open the app under **Enterprise applications**,
set **Assignment required** to **Yes** on **Properties**, and assign people
or groups on **Users and groups**.

### Google Workspace

1. In the Google Cloud console, **APIs & Services → Credentials → Create
   credentials → OAuth client ID**, type **Web application**, with the
   redirect URI above.
2. The issuer URL is `https://accounts.google.com`.

Only addresses in your verified domains can sign in, so personal Gmail
accounts are refused.

## 3. Turn it on

- **Single sign-on**: people choose **Sign in with SSO** on the sign-in page
  and enter their work email. You can link straight to it:
  `https://verdyx.dev/login?sso=1`. Turning it on checks that Verdyx can read
  your provider's configuration.
- **New people join as**: someone who signs in through SSO for the first time
  joins the team with this role (member by default). They get a Verdyx
  account if they didn't have one.
- **Require single sign-on**: people with an address in your domains can't
  sign in or sign up with a password, Google or GitHub. The team's owners
  still can, so a problem with your identity provider can't lock the team
  out.

People who already have a Verdyx account with their work address keep it:
signing in through SSO links it. An account with Verdyx two-factor
authentication turned on still has to sign in with its password and code,
since the identity provider can't stand in for that second factor.

## Provisioning (SCIM)

On the **Sign-in** tab, under **Automatic provisioning**, press **Make a
token**. Copy it straight away: it's shown only once. Making a new one
replaces the old one.

| Setting | Value |
|---|---|
| SCIM base URL | `https://api.verdyx.dev/scim/v2` |
| Authentication | Bearer token: the provisioning token |
| Unique identifier | `userName`, the person's work email |

What it does:

| In your identity provider | In Verdyx |
|---|---|
| Assign someone the app | Makes their account if needed, and adds them to the team with the join role |
| Change their name | Updates it on the team's provisioning record |
| Unassign them, deactivate or delete them | Removes them from the team and stops their team API keys |
| Reassign them | Adds them back |

Removing someone from the team doesn't delete their Verdyx account or the
scans they made for themselves: those stay theirs. Scans they saved to the
team stay with the team. Team owners are never removed by provisioning, so
the team always keeps an owner. Groups aren't supported: assign people, or
assign a group so its members are provisioned one by one.

### Okta

1. On the OIDC app's **General** tab, choose **Edit** and set
   **Provisioning** to **SCIM**.
2. On the new **Provisioning** tab, under **Integration**:
   - **SCIM connector base URL**: `https://api.verdyx.dev/scim/v2`
   - **Unique identifier field for users**: `userName`
   - **Supported provisioning actions**: **Push New Users** and **Push
     Profile Updates**
   - **Authentication Mode**: **HTTP Header**, with the provisioning token
3. Press **Test Connector Configuration**, then **Save**.
4. Under **Provisioning → To App**, enable **Create Users**, **Update User
   Attributes** and **Deactivate Users**.

### Microsoft Entra ID

1. Open the app under **Enterprise applications** (the app registration
   created one with the same name) and choose **Provisioning → Get started**.
2. Set **Provisioning Mode** to **Automatic**, then:
   - **Tenant URL**: `https://api.verdyx.dev/scim/v2`
   - **Secret Token**: the provisioning token
3. Press **Test Connection**, then **Save**.
4. Under **Mappings → Provision Microsoft Entra ID Users**, check that
   `userName` maps to `userPrincipalName` (or to `mail`, if people's sign-in
   names aren't their addresses). Only `userName`, `active`, `displayName`,
   `name.givenName`, `name.familyName` and `externalId` are used; you can
   remove the other mappings.
5. Set **Provisioning Status** to **On**.

Entra provisions every 40 minutes or so. Use **Provision on demand** to try
one person straight away.

## API

These need an owner's or admin's session or personal API key. Team API keys
can't use them.

| Request | What it does |
|---|---|
| `GET /api/v1/orgs/{id}/sso` | Domains, SSO settings, redirect URI, provisioning status |
| `PUT /api/v1/orgs/{id}/sso` | `{"issuer", "clientId", "clientSecret", "enabled", "required", "joinRole"}`. Leave `clientSecret` out to keep the stored one |
| `POST /api/v1/orgs/{id}/sso/domains` | `{"domain": "example.com"}`. Returns the TXT record |
| `POST /api/v1/orgs/{id}/sso/domains/{domain}/verify` | Checks the TXT record |
| `DELETE /api/v1/orgs/{id}/sso/domains/{domain}` | Removing the last verified domain turns SSO off |
| `POST /api/v1/orgs/{id}/sso/scim-token` | A new provisioning token, returned once |
| `DELETE /api/v1/orgs/{id}/sso/scim-token` | Stops provisioning |

The SCIM endpoints are `/scim/v2/Users` (list, with `filter=userName eq
"…"`, create), `/scim/v2/Users/{id}` (read, replace, patch, delete),
`/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes` and
`/scim/v2/Schemas`. A user's SCIM `id` is their Verdyx user id.

Every change is written to the team's activity log: SSO turned on or off,
domains added, verified and removed, tokens made and revoked, people who
joined through SSO, and people provisioned and removed.

## How it's kept safe

- The sign-in uses the authorization code flow with PKCE and a nonce. The ID
  token's signature is checked against the provider's published keys, along
  with its issuer, audience, expiry and nonce. Tokens signed with a shared
  secret or with no signature are refused.
- The issuer URL must be https, and Verdyx only connects to public
  addresses, so it can't be pointed at internal services.
- Only addresses in the team's verified domains are accepted, from both
  sign-in and provisioning.
- The client secret is stored encrypted. Only a fingerprint of the
  provisioning token is stored.

## If it doesn't work

The sign-in page says what went wrong:

| Message | What to check |
|---|---|
| Single sign-on isn't set up for that email domain | The domain isn't verified, or SSO is off |
| Your identity provider refused the sign-in, or couldn't be reached | The issuer URL, client ID or client secret is wrong, the secret expired, or the redirect URI in the provider doesn't match exactly |
| Your identity provider signed you in with an address outside your team's verified domains | The person's address is in a domain you haven't verified, or (Entra) their sign-in name isn't their address: add the `email` claim |
| Your identity provider didn't send an email address | Allow the `email` scope (Okta), or add the `email` optional claim (Entra) |
| That sign-in took too long or was opened in another browser | Start again from the sign-in page, in one browser |

For provisioning, your provider's logs show Verdyx's answer. `401` means the
token is wrong or was replaced. `400` with *isn't in one of the team's proven
domains* means the person's `userName` isn't an address in a verified domain.
