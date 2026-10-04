# Wakam (YesWeHack) — Recon + High-Severity Test Plan

> Scope (from program): `www.wakam.com` (Medium), `*.wakam.com` (Low),
> `ftps://lpa-ftp-01.lpa-insurance.eu` (Medium), `ftps://lpa-ftp-02.la-parisienne.fr` (Medium).
> **Out of scope:** `*.dify.wakam.com`, and anything not in the scope list (this
> likely includes `wakamforgood.com` — it is in the program *description* but NOT
> in the formal Scopes table, so treat it as OOS until confirmed).
> **Rules:** no DoS, no heavy/automated scanners, no data destruction/exfiltration,
> no disclosure. **Required user-agent suffix:** ` -BugBounty-wakam-75002 `.
> Open Redirect on `id.wakam.com` / `id.uat.wakam.com` is **non-qualifying**.
>
> NOTE: This file is recon + a test plan only. No vulnerability here is confirmed —
> every item below must be validated by sending real requests from an authorized
> host (this cloud container's network egress is blocked from reaching wakam.com).

## 1. Subdomains discovered (passive, via search)

| Host | Scope | What it is | Why interesting |
|------|-------|-----------|-----------------|
| `www.wakam.com` | ✅ Medium | Marketing/showcase site | Forms (complaints/claims/contact), open-redirect params, any CMS |
| `developer.wakam.com` | ✅ `*.wakam.com` | API developer portal (has `/signin`) | Auth, API key handling, IDOR on profile/subscription keys, interactive "Try it" console |
| `dvdeveloper.wakam.com` | ✅ `*.wakam.com` | **DEV** developer portal | Lower-hardened env; same surface as prod portal; debug endpoints |
| `status.wakam.com` | ✅ `*.wakam.com` | Status page | Usually 3rd-party hosted; low value; check for info leak / takeover |
| `id.wakam.com` | ✅ `*.wakam.com` | Identity / SSO | Auth bypass, IDOR, privesc qualify (open redirect does NOT) |
| `id.uat.wakam.com` | ✅ `*.wakam.com` | **UAT** identity / SSO | UAT often weaker; same auth tests |
| `*.dify.wakam.com` | ❌ OOS | Dify AI chatbot | Skip entirely |
| `wakam-selfservice.stoplight.io` | ❌ OOS | API docs on Stoplight (not a wakam.com asset) | Use only as a *map* of API endpoints to test on in-scope hosts |

**Still to enumerate** (portals referenced by Wakam but host not yet found — look for these):
Distributors Portal, Reinsurers Portal, Partner Data Exchange. Likely candidates to resolve:
`distributors.`, `distributor.`, `reinsurers.`, `reinsurer.`, `partners.`, `partner.`,
`exchange.`, `data.`, `connect.`, `extranet.`, `app.`, `my.`, `portal.`, `api.`,
`api.uat.`, `gateway.`, `auth.`, `account.` — each `.wakam.com`.

### Recon still owed (run from your authorized host)
- Cert transparency: `crt.sh`, `certspotter`, `censys` for `%.wakam.com`.
- Passive DNS: VirusTotal, SecurityTrails, AlienVault OTX.
- `web.archive.org` CDX for `developer.wakam.com` + `www.wakam.com` (old endpoints/params).
- Resolve candidate list above; note which are live, their tech stack, and WAF.
- Pull the Stoplight/OpenAPI spec from the dev portal — it is the API endpoint catalog.

## 2. API endpoints known (from dev-portal docs) — test on the in-scope API host

From the developer portal: `POST /getprice`, `POST /getPrice/simulate`, `POST /subscribe`,
`POST /policies`, `POST /cancel`, `GET /getClaims`. Auth is a subscription API key
(sandbox "Souscription-Développement", preprod, prod), key shown in Profile.

These are the richest surface for the classes you want. Get a sandbox key first (free, 100 calls/mo).

## 3. Per-class test plan (high-severity only)

### IDOR with sensitive data  ← highest likelihood on this target
- `GET /getClaims`, `/policies/{id}`, `/subscribe` responses: swap policy IDs / claim IDs /
  customer IDs across two sandbox accounts (register a 2nd). Can account A read account B's
  policy/claim/PII? That's the money bug here (insurance = PII, policy data).
- Developer portal **Profile / Subscription keys**: can you read another user's API key by
  ID/GUID manipulation? Exposed key = account takeover of their API access.
- Look for sequential/UUID object refs in any `GET ?id=` / path param. Test with a low-priv key.

### Horizontal & vertical privesc
- Two sandbox accounts (horizontal): access each other's objects.
- Role boundaries (vertical): can a dev-subscription key call prod-only or admin-only
  endpoints (e.g. force a live `POST /subscribe`/`/policies` outside sandbox)? Check if the
  env is enforced server-side or just by which key you send.
- On `id.wakam.com`: tamper JWT/role claims, `role`/`scope` params, forced browsing to
  admin paths after normal login.

### SQL injection
- Every API parameter that looks like a filter/lookup: `getClaims` date/status/id filters,
  `getprice` fields, any `?search=`/`?id=` on the portals. Test error-based + time-based
  (`'`, `' OR '1'='1`, `;WAITFOR DELAY`, `pg_sleep`), **low-rate, no automated sqlmap runs**.
  Azure/MSSQL stack is likely (dev portal mentions Azure APIM patterns).

### SSRF / XXE / LFI / RFI
- SSRF: any endpoint taking a URL/callback/webhook (partner integration, "connect your
  funnel", TPA/claims webhook config). Point at `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  (Azure IMDS — needs `Metadata:true` header) and at a collaborator host. Azure IMDS creds = critical.
- XXE: any XML-accepting endpoint (SOAP-ish policy/claims import, file upload). Send DOCTYPE
  with external entity to a collaborator; try `file:///etc/passwd` / `file:///C:/windows/win.ini`.
- LFI/RFI: file/path/template params, document download by name, `?file=`, `?lang=`, `?template=`.

### RCE
- Usually chains from the above (XXE→file read→config→creds; SSTI in any templated output;
  deserialization in .NET/Java endpoints; file upload that reaches an exec path). Check the
  "Try it" console and any upload (claims documents?) for unsafe handling.
- Look for known-CVE software on discovered hosts (but PoC required; <30-day CVEs non-qualifying).

### FTPS scopes (`lpa-ftp-01` / `lpa-ftp-02`)
- Anonymous/weak-cred access, directory traversal, world-readable sensitive files.
  Credentialed only — don't brute force (rate-limit rule). Report exposed data access, not just "port open".

## 4. Reporting notes (YesWeHack)
Each report needs: clear description + exploit mechanics + business impact + remediation,
screenshot PoC showing final impact, and full repro steps/payloads. First-reporter only;
systemic-dup rewards decay. Keep PoCs minimal and non-destructive. I can draft any of these
reports once you have a verified finding + the raw request/response.
