# Findings Register — Birthday Memory Security Assessment

**Assessment:** CYBR 4550 Operation Candlelight — Red Team (Track A)
**Target:** Birthday Memory (React / Express / PostgreSQL), own fork, localhost on Kali VM
**Methodology:** OWASP WSTG
**Date:** 2026-10-05

CVSS v3.1 base scores. Vectors are stated in full; see the board report for per-metric justification. Evidence paths are relative to the repository root.

| ID | Title | OWASP | Component | CVSS Score | Severity | Vector | Status | Evidence |
|----|-------|-------|-----------|-----------|----------|--------|--------|----------|
| F-01 | Unauthenticated read of all PII records | A01 | `GET /api/birthdays` | 7.5 | High | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | Confirmed | `security/evidence/A01-broken-access-control/01-read-unauth.txt` |
| F-02 | Unauthenticated record creation | A01 | `POST /api/birthdays` | 7.5 | High | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | Confirmed | `.../A01-broken-access-control/02-create-unauth.txt` |
| F-03 | Unauthenticated record modification | A01 | `PUT /api/birthdays/:id` | 7.5 | High | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | Confirmed | `.../A01-broken-access-control/03-modify-unauth.txt` |
| F-04 | Unauthenticated record deletion | A01 | `DELETE /api/birthdays/:id` | 7.5 | High | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | Confirmed | `.../A01-broken-access-control/04-delete-unauth.txt`, `05-delete-verify-404.txt` |
| F-05 | No authentication or authorization layer (absent by design) | A07 / A04 | Entire API | 9.1 | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | Confirmed | F-01 through F-04 (demonstrated); `server/src/index.js`, `routes.js` (no auth middleware) |
| F-06 | PII stored unencrypted at rest | A02 | PostgreSQL `birthdays` table | 6.5 | Medium | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | Confirmed | `.../A02-crypto-failures/01-pii-plaintext-at-rest.txt` |
| F-07 | DB connection unencrypted by default; certificate validation disabled when TLS enabled | A02 | `server/src/db.js:16` | 5.9 | Medium | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | Confirmed | `.../A02-crypto-failures/03-db-ssl-config.txt` |
| F-08 | Default database credentials committed to public repository | A08 / A05 | `server/src/db.js`, `docker-compose.yml` | 9.8 | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Confirmed | `.../A08-integrity-failures/01-secret-in-container-env.txt`; `db.js` defaults |
| F-09 | Application database role is superuser (excessive privilege) | A05 / A04 | PostgreSQL role `birthday` | 8.8 | High | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | Confirmed | `.../A02-crypto-failures/02-db-role-superuser.txt` |
| F-10 | Database port published on all interfaces (network-reachable) | A05 | `docker-compose.yml` ports | 8.6 | High | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | Confirmed | `docker-compose.yml`; LAN-IP connection evidence |
| F-11 | Permissive CORS policy (wildcard origin) | A05 | `server/src/index.js:9` | 5.3 | Medium | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | Confirmed | `.../A05-security-misconfig/01-cors-and-headers.txt`, `02-cors-rootcause.txt` |
| F-12 | Missing security response headers; framework disclosure | A05 | `server/src/index.js` | 3.7 | Low | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Confirmed | `.../A05-security-misconfig/01-cors-and-headers.txt` |
| F-13 | No audit trail for create/modify/delete operations | A09 | `server/src/index.js` (no logging middleware) | 5.3 | Medium | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | Confirmed | `.../A09-logging-monitoring/01-no-logging-middleware.txt` |
| F-14 | Known vulnerable components in container image | A06 | `postgres:16-alpine` (`gosu` binary) | 7.5 | High | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | Confirmed | `.../A06-vulnerable-components/01-trivy-high-crit.txt`, `02-trivy-full.txt` |
| F-15 | Mutable image tag; no digest pin; no SBOM | A08 | `docker-compose.yml` | 5.9 | Medium | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` | Confirmed | `.../A08-integrity-failures/02-mutable-image-tag.txt` |
| F-16 | Container runs as root | Container | `thebirthdates-db` | 6.5 | Medium | `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` | Confirmed | `.../container/01-runtime-user-root.txt`, `03-hostconfig-privileges.txt` |
| F-17 | Container secrets readable via standard Docker commands | Container / A08 | `thebirthdates-db` env | 5.5 | Medium | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | Confirmed | `.../A08-integrity-failures/01-secret-in-container-env.txt` |
| F-18 | No container resource limits (unbounded) | Container | `thebirthdates-db` | 5.3 | Medium | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` | Confirmed | `.../availability/04-no-resource-limits.txt` |
| F-19 | Unbounded query results; no pagination or rate limiting | Availability / A04 | `GET /api/birthdays`, `index.js` | 5.3 | Medium | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` | Confirmed | `.../availability/01-unbounded-read.txt`, `02-limit-param-ignored.txt`, `03-no-rate-limit.txt` |
| F-20 | Insecure design: trust-everything posture (no auth, least privilege, audit, or bounds) | A04 | System architecture | 9.1 | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | Confirmed | Synthesis of F-05, F-08, F-09, F-13, F-16, F-19 |
| F-21 | SQL injection | A03 | `GET /api/birthdays` (month filter, `:id`) | 0.0 | None | N/A | Not Vulnerable (tested) | `.../A03-injection/01-and-1eq2-discriminator.txt`, `02-quote-syntax-probe.txt`, `04-parameterized-query.txt` |
| F-22 | Server-Side Request Forgery | A10 | Entire API | 0.0 | None | N/A | Not Applicable | `.../A10-ssrf/01-no-outbound-http.txt` |

## Status summary

- **Confirmed Vulnerable:** F-01 through F-20 (20 findings)
- **Not Vulnerable (tested):** F-21 (SQL injection — parameterized queries + integer validation, verified by discriminating payloads)
- **Not Applicable:** F-22 (SSRF — no endpoint accepts a URL or makes a user-controlled outbound request)

## Notes on scoring

- F-08 (default credentials in public repo) is scored 9.8 because the credentials are network-reachable (F-10) and grant a superuser role (F-09): remote, no privilege required, full confidentiality/integrity/availability impact.
- F-09 uses Scope:Changed (`S:C`) because a superuser DB role can affect resources beyond the application's own data (the entire cluster, and potentially the host via `COPY ... TO PROGRAM`).
- F-16 uses `AV:L` because exploiting container-root requires an existing foothold (a container escape primitive); root alone is not remotely exploitable but widens blast radius.
- F-21 and F-22 carry no CVSS score; a tested-negative and a not-applicable result have no base score, but are listed for coverage completeness as the methodology requires.

