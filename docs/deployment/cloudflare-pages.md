# Deploying the Verdyx frontend on Cloudflare Pages (free)

Hosts the React app on Cloudflare's edge for **$0, with no card required**, and
proxies `/api/*` to whatever backend you attach later.

This is deliberately incremental: step 1 gets a public HTTPS URL today with no
backend at all, and the app degrades to empty states rather than errors. Attach
the API in step 4 once `api-gateway` has a home.

---

## What works without a backend

| Page | Standalone |
|---|---|
| `/`, `/pricing`, `/api`, 404 | ✅ fully |
| `/features`, `/how-it-works`, `/use-cases` | redirect to home sections |
| `/dashboard`, `/marketplace`, `/profile`, `/analysis/:id` | renders, empty states |
| `/login`, `/register`, password reset | renders, submit fails until step 4 |

The trust metrics on the landing page render `—` rather than invented figures
(`formatMetric` in `client/src/pages/home.tsx`), so an unattached deployment
looks unfinished-but-honest, not broken.

## 1. Create the project

Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** →
pick `deep60/Verdyx`.

## 2. Build settings

These matter — the repo is a monorepo and Vite writes outside its own root.

| Setting | Value |
|---|---|
| Production branch | `main` |
| **Root directory** | `frontend` |
| Build command | `npm run build` |
| **Build output directory** | `dist/public` |

Add an environment variable **`NODE_VERSION` = `22`**. Pages' default Node is
older than this project expects.

`functions/` sits at the root directory and is picked up automatically — no
configuration needed.

## 3. Deploy

Save and deploy. First build takes ~2 minutes and yields
`https://<project>.pages.dev`. Every push to `main` redeploys; pull requests get
their own preview URL.

Check `/dashboard` directly (not via in-app navigation) to confirm the SPA
fallback in `client/public/_redirects` is working — without it that URL 404s.

## 4. Attach the backend (later)

Once `api-gateway` is running somewhere public, set one variable:

**Settings → Environment variables → `API_GATEWAY_URL`** =
`https://your-gateway.example.com`

Then redeploy. `functions/api/[[path]].ts` picks it up and forwards every
`/api/*` call, normalizing paths to the gateway's `/api/v1/…` form exactly as
the Node BFF in `server/routes.ts` does.

Until that variable is set, `/api/*` returns 503 with
`{"error": "API Gateway unavailable"}` — the same shape the Node BFF returns, so
the UI handles it identically.

### Why proxy instead of calling the backend directly

`client/src/lib/queryClient.ts` fetches **relative** URLs with
`credentials: "include"`. Pointing the app at a cross-origin backend would
require CORS on the gateway plus `SameSite=None; Secure` cookies. Proxying at
the edge keeps everything same-origin and needs no code change.

## 5. Custom domain (optional)

**Custom domains → Set up a domain.** If the domain's DNS is on Cloudflare this
is automatic; otherwise add the CNAME they show you. TLS is issued
automatically.

---

## Notes

- **Deploying by hand**, without Git:
  ```sh
  cd frontend && npm run build
  npx wrangler pages deploy dist/public --project-name=verdyx
  ```
  Note this uploads static assets only — `functions/` is included only when
  wrangler runs from the directory containing it.
- **Functions are not covered by `tsc -b`.** `tsconfig.json` includes only
  `client/src`, `shared`, and `server`, so a type error in `functions/` will not
  fail `npm run build` — it surfaces at deploy time instead.
- **Free tier limits:** unlimited requests and bandwidth for static assets;
  Functions get 100,000 invocations/day. Ample for a proxy at this stage.
