# SafeMail X AI Security Work Status

Last updated: 2026-07-24

## What this work covers

This security work covers:

- The React Native mobile app in `trustmail-mobile/`.
- The backend API that the mobile app uses.
- The mobile app's login, session, scanning, upload, Gmail, notification, and OAuth flows.
- The deployed mobile API and its production configuration.

The separate `safemailx-website/` frontend is not being tested or changed because it has not been deployed and is outside this request.

## Simple explanation of the goal

The goal is to make it difficult for an attacker to:

- Use the API without logging in.
- Read another user's scans or reports.
- Guess passwords or flood the scan service.
- Upload dangerous or oversized files.
- Make the server connect to private internal addresses.
- Steal mobile session tokens through logs, deep links, or insecure storage.
- Abuse Gmail or Google OAuth connections.

The existing mobile features must continue to work after the security changes.

## Work completed so far

### Analysis and security testing

- Read the supplied `SAFEMAILX_SECURITY_AUDIT.md` and mapped its checks to the current code.
- Reviewed the backend, mobile app, deployment files, authentication, uploads, OAuth, URL analysis, logging, and dependency configuration.
- Confirmed that mobile tokens are currently stored through Expo SecureStore.
- Confirmed that the mobile app still has two TypeScript errors before security changes.
- Ran the backend test suite: 220 tests ran, with 3 existing SMS corpus category failures and 5 skips.
- Ran the focused backend authentication/server tests successfully.
- Ran mobile `npx tsc --noEmit`; the two existing `App.tsx` type errors were fixed and the check now passes.
- Ran the mobile dependency audit; it reported 18 vulnerabilities, including one critical finding.
- Added focused security tests for private URLs, unsafe upload archives, one-use OAuth codes, token separation, and fail-closed production settings.
- Tested the working Render API with safe unauthenticated requests.
- Confirmed that protected API endpoints currently return data without authentication.
- Confirmed that the custom API hostname currently returns Cloudflare 530.
- Confirmed that production API documentation is publicly reachable.
- After the changes, the full backend suite ran 226 tests with 5 skips. The three remaining failures are the same pre-existing SMS corpus category mismatches; one OAuth logging-visibility assertion was restored and passes in a focused rerun.
- The focused authentication/server, LLM/prompt-injection, security-control, and affected OAuth tests pass. Mobile `npx tsc --noEmit` and Python syntax checks pass.

### Containment changes made

- EAS preview builds now use the currently working Render API URL instead of the unhealthy custom hostname.
- EAS production builds now have an explicit API URL instead of relying on an unsafe fallback.
- The Fly deployment configuration now enables production mode and requires authentication.

These repository changes do not automatically change the already-running Render environment; its provider settings still need to be updated and verified during deployment.

### Security protections implemented and smoke-tested

- Production-shaped backend deployments now fail to start when authentication is disabled, JWT secrets are weak, Gmail token encryption is missing/invalid, SQLite is selected, or Redis still points to localhost.
- Access and refresh tokens have explicit types. Refresh tokens cannot be used as API bearer tokens. Logout revokes the access token when Redis is available.
- Scan-event WebSockets now use a short-lived, one-time ticket tied to the scan owner. Access tokens are not placed in the WebSocket URL.
- Login failures use bounded rate limits and progressive account lockout. Production routes also have Redis-backed rate limiting with a safe local development fallback.
- Request bodies, form fields, text sizes, filenames, and uploads now have limits. Uploads reject path traversal, executable-looking content, and unsafe ZIP archives while keeping the supported extensions.
- URL scanning permits only HTTP(S) URLs and blocks local/private/link-local/reserved destinations before redirect analysis.
- OAuth return URLs are restricted to the SafeMail X mobile callback scheme. Mobile OAuth now returns a short-lived one-use exchange code instead of access and refresh tokens in a deep link.
- OAuth state is now single-use as well, so replaying an old signed callback state is rejected.
- Mobile API URL overrides are disabled in release builds, full OAuth deep-link logging is removed, and sign-out asks the backend to revoke the session before clearing SecureStore.
- OTP/reset-link logging was removed, LLM prompt fields are bounded/sanitized, and LLM output fields are type-checked and length-limited.
- The two pre-existing mobile TypeScript errors were fixed; `npx tsc --noEmit` now passes.

## Exact file-by-file change map

This section explains where the changes were made. “Backend” means the API used by the mobile app. The website is not included.

### Backend configuration and request protection

| File | What changed | Why it matters |
|---|---|---|
| `.env.example` | Added examples for production mode, CORS origins, request-size limits, login lockout, rate limits, and WebSocket time limits. | Makes the required security settings visible when configuring a deployment. |
| `fly.toml` | Set `SAFEMAILX_PRODUCTION=true` and `SAFEMAILX_REQUIRE_AUTH=true`. | Prevents a Fly deployment from accidentally running as an unauthenticated local-style API. |
| `src/server/settings.py` | Added production-mode detection and startup validation for authentication, JWT secret strength, persistent database, Redis, and encrypted Gmail token storage. | The API fails closed instead of starting with unsafe production defaults. |
| `src/server/security.py` | Added request body limits, production rate limiting, login-failure tracking/lockout, security response headers, and cache prevention for API/auth responses. | Limits flooding, oversized requests, browser caching, and common response-header weaknesses. |
| `src/server/app.py` | Registered the security middleware, restricted CORS methods/headers, disabled API docs in production, and added generic validation/server-error responses. | Reduces unnecessary public exposure and prevents raw internal errors from being returned to users. |

### Authentication and authorization

| File | What changed | Why it matters |
|---|---|---|
| `src/server/auth.py` | Added JWT IDs, explicit access/refresh token types, revocation checks, logout revocation, one-time WebSocket tickets, one-time OAuth exchange codes, and one-use OAuth state. | Stops refresh tokens being used as access tokens and reduces token replay/theft risk. |
| `src/server/app.py` | Added `/auth/logout`, `/auth/oauth/exchange`, authenticated scan-event ticket creation, scan ownership checks, and login lockout handling. | Ensures users can access only their own scan data and can end a session server-side. |
| `src/server/schemas.py` | Added the OAuth exchange request/response fields and maximum lengths for credentials, passwords, names, scan text, URLs, tokens, and settings lists. | Prevents unexpectedly huge or malformed input while keeping normal requests compatible. |
| `src/server/repository.py` | Made password-reset token insertion safely replace a duplicate token record. | Keeps reset requests reliable and invalidates an older record if a token is reused. |

### Uploads, URLs, and analysis input

| File | What changed | Why it matters |
|---|---|---|
| `src/server/uploads.py` | Added filename traversal checks, executable-content rejection, ZIP path traversal checks, archive entry limits, expansion limits, and compression-ratio checks. | Prevents dangerous filenames and common archive-bomb attacks before parsers process files. |
| `src/server/app.py` | Reads uploaded files in bounded chunks, validates upload content, validates scan modes, and rejects unsafe URLs before queuing/scanning. | Avoids loading unlimited upload data into memory and blocks unsafe destinations early. |
| `src/engines/url_analyzer.py` | Added HTTP/HTTPS-only validation and checks against loopback, private, link-local, reserved, multicast, and unspecified IP addresses before URL fetching/redirect analysis. | Prevents the server from being used to reach internal services through a submitted URL. |
| `src/engines/llm_analyzer.py` | Bounded and sanitized sender, subject, security context, and message text; limited raw model output; validated JSON shape, intent, tactics, and reasoning length. | Reduces prompt-injection, oversized-input, malformed-output, and log/debug exposure risks. |

### OAuth, email, and logging

| File | What changed | Why it matters |
|---|---|---|
| `src/server/app.py` | Restricted OAuth return URLs to the `safemailxai` mobile callback, removed access/refresh tokens from deep links, escaped callback HTML, and stopped returning provider exception details. | Prevents open redirects, token leakage through URLs, and raw third-party error disclosure. |
| `src/server/auth.py` | Stores OAuth handoff data as a short-lived one-use code, with Redis in production and a local-only fallback for development/tests. | The mobile app receives a temporary code instead of permanent session tokens in a link. |
| `trustmail-mobile/src/api.ts` | Added the OAuth-code exchange call and authenticated backend logout call. | Lets the mobile app safely convert the temporary code into a session and revoke it on sign-out. |
| `trustmail-mobile/App.tsx` | Parses only the expected SafeMail X OAuth callback, no longer reads tokens from deep-link URLs, removes full URL logging, and calls server logout before clearing local state. | Keeps tokens in SecureStore/in-memory state instead of exposing them in URLs or logs. |
| `src/server/mailer.py` | Removed OTPs and password-reset links from console output. | Secrets no longer appear in terminal logs. |
| `src/server/inline_scan_service.py` | Stopped logging the full submitted URL during instant URL scans. | Reduces the chance of sensitive query strings appearing in logs. |

### Mobile release configuration and compatibility

| File | What changed | Why it matters |
|---|---|---|
| `trustmail-mobile/eas.json` | Preview and production profiles now explicitly use `https://safemailx-ai.onrender.com`. | Prevents builds from using the currently unhealthy custom hostname or an unsafe fallback. |
| `trustmail-mobile/src/api.ts` | Release builds cannot change the API URL at runtime; developer builds still support local HTTP/HTTPS testing. | Protects released apps from being redirected to an attacker-controlled API. |
| `trustmail-mobile/App.tsx` | Fixed the existing invalid `sms` tab type and the toast callback type mismatch. | Restores a clean TypeScript check without removing the share-to-SMS feature. |
| `trustmail-mobile/src/session.ts` | No storage downgrade was made; access, refresh, and email values remain in Expo SecureStore. | Preserves encrypted mobile session storage. |

### Tests and documentation

| File | What changed | Why it matters |
|---|---|---|
| `tests/test_security_controls.py` | Added tests for private URL blocking, upload traversal/executable/archive checks, one-use OAuth codes, token separation, and production fail-closed settings. | Provides repeatable checks for the new security behavior. |
| `docs/security_audit_status.md` | Added this plain-language status, file map, test results, and remaining-work list. | Provides a handoff document for understanding and resuming the work. |

## What was deliberately not changed

- `safemailx-website/` was not tested or modified because the website is frontend-only, not deployed, and outside the requested mobile-app scope.
- Supported upload extensions were not removed.
- SecureStore was not replaced with AsyncStorage.
- The existing silent-refresh behavior and refresh-token error contract were preserved.
- Native certificate pinning was not guessed or added through an unverified dependency; it remains a release-build task requiring a compatible Expo/EAS native implementation.

## Current security issues still being fixed

1. The live Render API must have authentication enabled immediately and re-tested; repository changes cannot edit Render provider variables automatically.
2. Certificate pinning still needs a native Expo/EAS implementation and a controlled certificate-rotation process.
3. The custom API hostname still needs its Cloudflare/origin configuration repaired or formally retired.
4. Mobile dependency upgrades and automated security scans still need to be completed without breaking the Expo build.
5. Staging and controlled live tests still need to cover login, refresh, logout, scans, uploads, OAuth, and WebSockets with a dedicated test account.

## Planned phases

### Phase 1 — Containment and baseline

Set production authentication, establish one healthy mobile API URL, record the current test baseline, and keep a rollback path.

### Phase 2 — Authentication and authorization

Harden JWTs, refresh tokens, logout, WebSockets, scan ownership, production documentation, and generic error responses. **Implemented; focused auth/server tests passed after a compatibility adjustment.**

### Phase 3 — Abuse and input protection

Add rate limits, login backoff, strict request validation, body limits, upload limits, and safe error responses. **Implemented; upload and URL smoke checks passed.**

### Phase 4 — Files, URLs, OAuth, and logs

Secure uploads, SSRF-prone requests, OAuth state and redirects, Gmail token encryption, LLM input/output, regex processing, and logs. **Core protections implemented; production OAuth still depends on working Redis and deployment verification.**

### Phase 5 — Mobile protection

Fix TypeScript errors, lock release API URLs, remove sensitive deep-link logging, preserve SecureStore behavior, and add release certificate pinning. **TypeScript, URL locking, deep-link handling, and SecureStore-preserving sign-out are implemented; certificate pinning remains.**

### Phase 6 — Regression and release testing

Run backend tests, mobile checks, security tests, dependency audits, staging tests, and carefully limited live API checks using a dedicated test account.

## How we will avoid breaking features

- Keep existing API response shapes compatible.
- Add security fields and checks in a backward-compatible migration where possible.
- Test each mobile feature after every phase.
- Mock Gmail, Redis, LLM, and threat-intelligence providers in automated tests.
- Test legitimate uploads for every currently supported format.
- Keep the existing single-attempt silent refresh behavior.
- Use staging before production.
- Monitor login failures, refresh failures, scan success, upload failures, and server errors after deployment.
- Roll back a phase if existing functionality regresses.

## What is left before completion

- Finish the remaining backend verification and production provider configuration.
- Finish native mobile certificate pinning and compatible dependency work.
- Expand regression/security coverage after staging and production-provider verification.
- Update the live Render environment with production authentication settings.
- Repair and verify the canonical API hostname.
- Complete staging and controlled live testing.
- Re-run all required checks and record final results here.

## Important current baseline failures

These were present before the security implementation and must be handled separately:

- Three SMS corpus tests report category mismatches.
- Mobile TypeScript errors are fixed; the current `npx tsc --noEmit` check passes.
- Mobile dependency audit reports high/critical transitive vulnerabilities.

No website findings are included in this status because the website is out of scope.
