# sqlmap playbook (staged)

## Stage map

| Stage | sqlmap flag | Purpose | Stop and report |
|---|---|---|---|
| detect | (none) | injectable? technique, DBMS, columns | yes |
| tables | `--tables` | table names | yes |
| columns | `-T <table> --columns` | columns of one table | yes |
| dump | `-T <table> -C <cols> --dump` | selected data | yes |
| dbs / current-db | `--dbs` / `--current-db` | database names | optional |

Use one `--output-dir` for the whole engagement; only `detect` uses `--flush-session`.
Reset with `--flush-session` only when you intentionally want a fresh detection.

## Request recipes

### GET with query parameter

```
-u "http://host/path?keyword=1*&from=&to=" --cookie "NB_SID=..."
```

### POST form

```
-u "http://host/login" --data "username=1*&password=x" --cookie "..."
```

sqlmap treats `--data` as POST. Add `--method POST` only if the site requires it explicitly.

### POST JSON

```
-u "http://host/api/coupon" \
  --data '{"code":"WELCOME10*"}' \
  --headers "Content-Type: application/json
X-CSRF-Token: <token>" \
  --cookie "NB_SID=..."
```

- Put `*` inside the JSON string value.
- A valid base value (e.g. `WELCOME10`) is required for AND boolean tests; an empty base makes true/false both empty and produces a false negative.
- If the JSON payload needs a double quote, escape it as `\"`.

## Core flags

- `--batch` non-interactive; `--threads 1` always.
- `--level 1–3` more payloads; `--risk 1–2` more intrusive tests (never 3 here).
- `--dbms` skips fingerprinting when known.
- `--delay N` seconds between requests; use 1–3 on rate-limited targets.
- `--time-sec 5` time-based blind wait; keep 3–10.
- `--technique` B/E/U/S/T when you need to force a technique.
- `--union-cols` / `--union-char` when UNION needs help; a non-numeric `--union-char` can avoid reflective-value false negatives.
- `--string` a marker that appears only in the "true" response (boolean blind).
- `--output-dir` artifact root; CSV dumps land under `<out>/<host>/dump/<db>/`.

## Reading results

- `is vulnerable` → injectable. `Type:` / `Title:` / `Payload:` → technique and evidence.
- `appears to have N columns` → UNION column count.
- `back-end DBMS:` → DBMS.
- `retrieved:` rows during `--tables` / `--dump`.
- `dumped to CSV file '...'` → artifact path.
- `fetched data logged to text files under '...'` → log directory.

## Failure triage

- **302 → /login / 401** — cookie expired or wrong host. Re-copy Cookie; redo the baseline.
- **403 / Cloudflare challenge** — WAF, not "no vuln". Stop. Ask the owner to allowlist or give a staging URL. Do not spray `--tamper`/`--random-agent` on production.
- **429** — rate limit. Increase `--delay`, lower scope, wait. Never parallelize.
- **All 200, "not injectable"** — baseline empty, wrong parameter, or encoding/CSRF issue. Verify with a normal value and inspect the actual request.
- **500 burst + blank dump** — the app may cap input length or swallow SQL errors. Check its max length; use shorter manual payloads or ask the owner.
- **UNION false negative** — column count or reflected values; try `--union-cols N --union-char 1` or a distinctive string; `--string` for boolean.
- **Time-based unreliable** — increase `--time-sec`; avoid on slow/shared links.

## Artifacts and report

- Raw logs: `<output_dir>/<stage>.log`.
- Dumps: `<output_dir>/<host>/dump/<db>/<table>.csv`.
- Final report: target/scope, entry, request, technique/payloads, data exposed, fix, artifacts, not-tested.
- Mask cookies, CSRF tokens, phone numbers, emails, and any personal data.
