#!/usr/bin/env python3
"""
 Capture evidence script for the repository 

This script will rerun each command during the testing and save the results as evidence in security/evidence/


"""
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

# --- configuration ---
BASE_URL = "http://localhost:4000"
DB_HOST = "localhost"
DB_PORT = "5544"
DB_USER = "birthday"
DB_NAME = "thebirthdates"
DB_PASS = "birthday"  # This is the known vulnerable credential that existed during the baseline analysis. 
IMAGE = "postgres:16-alpine"
CONTAINER = "thebirthdates-db"

EVIDENCE_ROOT = Path("security/evidence")

# Refuse to run unless the target is loopback.
assert "localhost" in BASE_URL or "127.0.0.1" in BASE_URL, "Target must be localhost."


# --- helpers ---
def _dest(category: str, name: str) -> Path:
    """Create security/evidence/<category>/ and return the full path to <name> inside it."""
    folder = EVIDENCE_ROOT / category
    folder.mkdir(parents=True, exist_ok=True)
    return folder / name


def _write(dest: Path, header_lines: list[str], stdout: str, stderr: str = "") -> None:
    """Shared writer: timestamp + header + stdout/stderr blocks."""
    with open(dest, "w") as f:
        f.write(f"# Captured: {datetime.now().isoformat()}\n")
        for line in header_lines:
            f.write(f"# {line}\n")
        f.write("\n--- STDOUT ---\n")
        f.write(stdout)
        if stderr.strip():
            f.write("\n--- STDERR ---\n")
            f.write(stderr)


# --- capture functions ---
def capture_http(category: str, name: str, curl_args: list[str]) -> subprocess.CompletedProcess:
    """Run a curl -i request and save the full transcript. Returns the result
    so callers that need the response body (e.g. to parse an id) can use it."""
    dest = _dest(category, name)
    cmd = ["curl", "-i", "-s", *curl_args]
    result = subprocess.run(cmd, capture_output=True, text=True)
    _write(dest, [f"Command: {' '.join(cmd)}"], result.stdout, result.stderr)
    print(f"[+] {category}/{name}")
    return result


def capture_shell(category: str, name: str, command: list[str], env_extra: dict | None = None) -> None:
    """Run a shell command and save stdout+stderr. env_extra adds vars to the
    child environment without putting them on the command line (used for
    PGPASSWORD so the DB password never shows up in a process listing)."""
    dest = _dest(category, name)
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    _write(dest, [f"Command: {' '.join(command)}"], result.stdout, result.stderr)
    print(f"[+] {category}/{name}")


def capture_file(category: str, name: str, src: str, start: int, end: int) -> None:
    """Copy lines start..end (inclusive, 1-indexed) from src into evidence,
    prefixed with their real line numbers so the citation is unambiguous."""
    dest = _dest(category, name)
    lines = Path(src).read_text().splitlines()
    # file line 1 == list index 0; end inclusive
    selected = lines[start - 1:end]
    body = "\n".join(f"{start + i:4} | {text}" for i, text in enumerate(selected))
    _write(dest, [f"Source: {src}", f"Lines: {start}-{end}"], body)
    print(f"[+] {category}/{name}")


def _psql(category: str, name: str, sql: str) -> None:
    """Run one SQL statement through psql as the app's DB role, password via
    PGPASSWORD env so it stays off the command line."""
    cmd = ["psql", "-h", DB_HOST, "-p", DB_PORT, "-U", DB_USER, "-d", DB_NAME, "-c", sql]
    capture_shell(category, name, cmd, env_extra={"PGPASSWORD": DB_PASS})


def capture_a01_crud_chain() -> None:
    """A01 write verbs, idempotent and self-cleaning.

    The three mutating verbs are chained in one function because each depends
    on the previous: create returns a new record id, which is then the target
    of the modify and the delete. Doing it this way means every run creates its
    OWN throwaway record, mutates and deletes THAT, and never touches seed data,
    so the script is safe to re-run. curl's response body is captured from
    stdout, the id is parsed out of the JSON, and used for the next request.
    """
    cat = "A01-broken-access-control"

    # CREATE - unauthenticated POST
    create = capture_http(cat, "02-create-unauth.txt", [
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", '{"firstName":"PENTEST","lastName":"DELETE-ME","birthdate":"2001-01-01"}',
        f"{BASE_URL}/api/birthdays",
    ])

    # Parse the new id out of the response. curl -i prints headers then body;
    # the body is the last JSON object, so split on the blank line.
    new_id = None
    try:
        body = create.stdout.split("\r\n\r\n", 1)[-1].split("\n\n", 1)[-1].strip()
        new_id = json.loads(body).get("id")
    except (json.JSONDecodeError, IndexError):
        pass

    if not new_id:
        print("[!] Could not parse created id; skipping modify/delete. "
              "Is the API up at " + BASE_URL + "?")
        return

    # MODIFY - unauthenticated PUT against the record we just made
    capture_http(cat, "03-modify-unauth.txt", [
        "-X", "PUT",
        "-H", "Content-Type: application/json",
        "-d", '{"firstName":"PENTEST","lastName":"MODIFIED-BY-PENTEST","birthdate":"2001-01-01"}',
        f"{BASE_URL}/api/birthdays/{new_id}",
    ])

    # DELETE - unauthenticated DELETE of the same record (also cleans up)
    capture_http(cat, "04-delete-unauth.txt", [
        "-X", "DELETE", f"{BASE_URL}/api/birthdays/{new_id}",
    ])

    # VERIFY gone - GET the id back, expect 404
    capture_http(cat, "05-delete-verify-404.txt", [
        f"{BASE_URL}/api/birthdays/{new_id}",
    ])


def main() -> None:
    # ---------- A01 Broken Access Control ----------
    # READ - unauthenticated GET returns all PII
    capture_http("A01-broken-access-control", "01-read-unauth.txt",
                 [f"{BASE_URL}/api/birthdays"])
    # CREATE / MODIFY / DELETE chain (idempotent)
    capture_a01_crud_chain()

    # ---------- A02 Cryptographic Failures ----------
    # at-rest: PII stored in plaintext, read straight out of the table
    _psql("A02-crypto-failures", "01-pii-plaintext-at-rest.txt",
          "SELECT first_name, last_name, email, phone FROM birthdays LIMIT 3;")
    # DB role privilege: superuser
    _psql("A02-crypto-failures", "02-db-role-superuser.txt", "\\du")
    # in-transit: the ssl config in db.js (rejectUnauthorized:false when enabled)
    capture_file("A02-crypto-failures", "03-db-ssl-config.txt",
                 "server/src/db.js", 1, 27)

    # ---------- A05 Security Misconfiguration ----------
    # CORS wildcard + X-Powered-By visible in response headers
    capture_http("A05-security-misconfig", "01-cors-and-headers.txt",
                 ["-X", "OPTIONS", f"{BASE_URL}/api/birthdays"])
    # root cause: bare cors() in index.js
    capture_file("A05-security-misconfig", "02-cors-rootcause.txt",
                 "server/src/index.js", 9, 10)

    # ---------- A06 Vulnerable and Outdated Components ----------
    capture_shell("A06-vulnerable-components", "01-trivy-high-crit.txt",
                  ["trivy", "image", "--severity", "CRITICAL,HIGH", IMAGE])
    capture_shell("A06-vulnerable-components", "02-trivy-full.txt",
                  ["trivy", "image", IMAGE])

    # ---------- A08 Integrity Failures ----------
    # secret readable back out of the container
    capture_shell("A08-integrity-failures", "01-secret-in-container-env.txt",
                  ["docker", "inspect", CONTAINER, "--format", "{{json .Config.Env}}"])
    # mutable image tag (no digest pin) in compose
    capture_file("A08-integrity-failures", "02-mutable-image-tag.txt",
                 "docker-compose.yml", 1, 30)

    # ---------- A09 Logging and Monitoring Failures ----------
    # no logging middleware anywhere in the request path
    capture_file("A09-logging-monitoring", "01-no-logging-middleware.txt",
                 "server/src/index.js", 1, 31)

    # ---------- Container-specific ----------
    capture_shell("container", "01-runtime-user-root.txt",
                  ["docker", "exec", CONTAINER, "whoami"])
    capture_shell("container", "02-runtime-user-id.txt",
                  ["docker", "exec", CONTAINER, "id"])
    capture_shell("container", "03-hostconfig-privileges.txt",
                  ["docker", "inspect", CONTAINER, "--format",
                   "User={{.Config.User}} CapAdd={{.HostConfig.CapAdd}} "
                   "CapDrop={{.HostConfig.CapDrop}} Privileged={{.HostConfig.Privileged}} "
                   "Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}}"])

    # ---------- A03 Injection (NEGATIVE result - tested, not vulnerable) ----------
    # discriminator: AND 1=2 returns full set (payload dropped, not injected)
    capture_http("A03-injection", "01-and-1eq2-discriminator.txt",
                 ["-G", f"{BASE_URL}/api/birthdays", "--data-urlencode", "month=2 AND 1=2"])
    # syntax probe: a lone quote returns 200, no SQL error
    capture_http("A03-injection", "02-quote-syntax-probe.txt",
                 ["-G", f"{BASE_URL}/api/birthdays", "--data-urlencode", "month=1'"])
    # baseline: valid month filters correctly (proves the filter works at all)
    capture_http("A03-injection", "03-valid-month-baseline.txt",
                 ["-G", f"{BASE_URL}/api/birthdays", "--data-urlencode", "month=10"])
    # root cause: parameterized query + integer validation in routes.js
    capture_file("A03-injection", "04-parameterized-query.txt",
                 "server/src/routes.js", 14, 35)

    # ---------- Availability ----------
    # unbounded read: full table in one request, limit param ignored
    capture_http("availability", "01-unbounded-read.txt",
                 [f"{BASE_URL}/api/birthdays"])
    capture_http("availability", "02-limit-param-ignored.txt",
                 ["-G", f"{BASE_URL}/api/birthdays", "--data-urlencode", "limit=1"])
    # no rate-limit middleware present
    capture_shell("availability", "03-no-rate-limit.txt",
                  ["grep", "-riE", "rate.?limit|express-rate-limit|slowdown|throttle",
                   "server/src", "server/package.json"])
    # no container resource caps
    capture_shell("availability", "04-no-resource-limits.txt",
                  ["docker", "inspect", CONTAINER, "--format",
                   "Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}} "
                   "PidsLimit={{.HostConfig.PidsLimit}}"])

    # ---------- A10 SSRF (NEGATIVE - not applicable) ----------
    # no outbound-request libraries in the server source
    capture_shell("A10-ssrf", "01-no-outbound-http.txt",
                  ["grep", "-riE", "fetch|axios|http.get|request\\(|got\\(", "server/src"])

    print("\nDone. Evidence written under", EVIDENCE_ROOT)


if __name__ == "__main__":
    main()
