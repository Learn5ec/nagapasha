# Current Implementation — nagapasha

> Last updated: 2026-08-25
> Test count: 392 passing

## Phase 0 — cURL Ingestion & Recon (Core Engine)

### Stage 1: cURL Parser (`nagapasha/stages/stage01_parse.py`)
- `parse_curl(curl_command: str) -> RequestModel` — parses any curl command
- Type inference (ordered): UUID, email, filename, date, int, boolean, free_text
- Auth parameter detection (Authorization, X-Auth-Token, X-API-Key, Cookie)
- Supports: `-X`, `-H`, `-d`, `-d @file`, `--data-binary`, `--data-urlencode`, `-b` (cookies), `-u` (basic auth), `-k`
- Boolean regex avoids conflict with int detection (`^(true|false|yes|no)`)

### Stage 2: Recon (`nagapasha/stages/stage02_recon.py`)
- `run_recon(request_model, runner, calibrate_count=5) -> ReconResult` — async orchestrator
- Auth validity check — replays request, confirms expected 2xx
- JWT detection & expiry watchdog — base64url decode, flags weak alg (none, HS128)
- Baseline capture — 3-5 calibrations for SHA-256 body fingerprinting, flakiness detection
- Rate-limit discovery from `X-RateLimit-*` / `Retry-After` headers
- WAF/CDN detection: Cloudflare, Akamai, AWS WAF, F5 BIG-IP, Sucuri, Imperva
- Tech stack auto-fingerprinting: Server, X-Powered-By, session cookie names, database hints from error pages
- `ReconResult` dataclass: auth_valid, auth_status, jwt_info, baseline_fingerprint, is_flaky, rate_limit_pps, rate_limit_config, tech_stack, waf_detected, waf_name

### Engine: Diff (`nagapasha/engine/diff.py`)
- `BaselineFingerprint` — status_code, content_length, body_hash, avg_response_time, header_names, body_preview
- `ResponseDelta` — is_no_diff, status_delta, content_length_delta, response_time_delta, has_reflected_payload, has_error_signature, is_confirmed_hit, is_near_miss
- 14 ERROR_SIGNATURES regexes (SQL errors, stack traces, path disclosure, etc.)
- `compute_delta()` — multi-check diff against baseline
- `check_flakiness()` — verifies baseline stability across N calibrations

### Engine: Rate Limiter (`nagapasha/engine/rate_limiter.py`)
- `RateLimitConfig(burst, refill_rate, backoff_multiplier=2.0, max_backoff=60.0)`
- `TokenBucketRateLimiter` — pure token bucket with async acquire
- 429 penalty: base penalty on first 429 (`1.0/refill_rate`), then scales with multiplier
- 2xx response reduces penalty debt

### Engine: Runner (`nagapasha/engine/runner.py`)
- `HttpRunner` — wraps httpx.AsyncClient with rate limiter integration
- `send()` — async, captures status/headers/body/elapsed, feeds 429/2xx to rate limiter
- `send_multiple()` — fires N times for baseline calibration

### Engine: JWT Watchdog (`nagapasha/engine/jwt_watchdog.py`)
- `JwtInfo` — is_jwt, header, payload, alg, exp, issued_at, is_expired, algorithm_flagged, flag_reason
- `decode_jwt(token)` — base64url decode, extract claims, flag weak alg
- `detect_jwts(headers, cookies)` — scan for JWT-shaped values
- `JwtWatchdog` — background asyncio task, pauses at exp-60s (configurable)

### Engine: Baseline (`nagapasha/engine/baseline.py`)
- `capture_baseline(runner, request_model, count=5)` — computes stable fingerprint

### Engine: Script Generator (`nagapasha/engine/script_generator.py`)
- `StaticScriptGenerator` — generates standalone executable Python scripts
- Uses `.replace()` with double-brace placeholders (`{{BASE_URL}}`) to avoid `.format()` conflicts
- `_sanitize_constant()` — safely embeds values as Python constants
- Generated scripts include embedded: rate limiter, JWT watchdog, payload loop, diffing engine

### Engine: Payload Loop (`nagapasha/engine/payload_loop.py`)
- `PayloadLoop` — drives sequential/batched payload firing
- `PayloadCandidate` — parameter, payload, attack_class, payload_tags, rationale
- `PayloadResult` — candidate, status_code, delta, elapsed, hit, near_miss, classification (HIT | NEAR-MISS | no-diff)
- Configurable: rate limit, max_requests, kill switch, JWT deadline, batch_size
- `run_payloads()` convenience function

### Engine: Triage (`nagapasha/engine/triage.py`)
- `TriageResult` — is_hit, is_no_diff, is_ambiguous, confidence, evidence
- `triage()` — heuristic classification: HIT (error signature/reflection), NO-DIFF, AMBIGUOUS (near-miss signals)
- Confidence scoring: 0.95 error sig, 0.90 reflection, 0.80 large status change, 0.50 near-miss, 0.30 body changed

### Database (`nagapasha/db/schema.py`)
- 5 tables: engagements, parameters, findings, audit_log, llm_calls
- `EngagementStore` — context manager with CRUD operations

### Utils
- `scope_guard.py` — max_requests=10000, scope confirmation, kill switch via asyncio.Event
- `notifications.py` — OS-native (osascript/notify-send) + Slack webhook

### CLI (`nagapasha/cli.py`)
- `parse` — parse curl → RequestModel (JSON or pretty print)
- `recon` — parse + recon with scope confirmation, saves to SQLite
- `generate` — parse + recon + output standalone Phase 1 script
- `run` — execute a generated Phase 1 script
- `full` — full pipeline: parse → recon → targeting → generate → execute

---

## Phase 1 — Executable Script Runner

### Targeting (`nagapasha/stages/stage03_targeting.py`)
- `run_targeting(request_model, auto=False)` — human checkpoint
- Rich table display of parameters with location, type, value, auth status
- Interactive: "Type indices to fuzz, 'all', or 'none'"
- Auto mode: fuzz all non-auth, non-flaky parameters

---

## Phase 2 — LLM Integration

### LLM Infrastructure (`nagapasha/llm/`)
- `runner.py` — `ClaudeRunner` subprocess wrapper for `claude` CLI
  - Structured JSON in/out, markdown fence extraction, stdout commentary handling
  - `ClaudeInvocationError` exception
- `contracts.py` — TypedDict schemas for all agent stages (Strategist, Librarian, Fitter, Specialist Input/Output)
- `prompts/` — System prompt templates:
  - `strategist.txt` — attack candidate generation
  - `librarian.txt` — payload sourcing
  - `fitter.txt` — placement/encoding/glue decisions
  - `specialist.txt` — near-miss pattern analysis

### Strategist (`nagapasha/stages/stage05_strategist.py`)
- `run_strategist(request_model, baseline, tech_stack, runner, timeout)` — LLM agent
- Input: RequestModel + baseline fingerprint + tech stack
- Output: list of attack candidates with parameter_index, attack_class, rationale, confidence, wstg_reference, recommended_payload_tags
- Heuristic fallback: `_guess_attack_class()` based on param name keywords (SQL, file, user) and location (path→traversal, header→IDOR)
- Fallback on runner failure or bad response

### Librarian (`nagapasha/stages/stage07_librarian.py`)
- `run_librarian(attack_classes, tech_stack, runner, timeout)` — offline-first payload sourcing
- Local KB at `nagapasha/llm/kb/*.json` with tag-based search
- Fallback to `get_default_payloads()` for: sql_injection, xss, lfi, idor, ssrf
- Optional LLM enrichment via `_enrich_with_llm()`

### Fitter (`nagapasha/stages/stage08_fitter.py`)
- `run_fitter(parameter, attack_class, payload, tech_stack, runner, timeout)` — placement decisions
- Heuristic fitting implements critical joining logic:
  - Path traversal: `../../etc/passwd` needs `/` glue
  - SQLi in query: needs `'` quote glue
  - XSS in query: needs URL encoding
  - JSON body: json_field_value placement
  - Headers: header_value placement
  - Cookies: URL encoding
- `apply_placement()` — constructs modified URLs from placement decisions
- Helper functions: `_replace_query_param`, `_prefix_query_param`, `_suffix_query_param`, `_wrap_query_param`, `_replace_path_segment`

---

## Phase 3 — Specialist Agent + Triage

### Specialist (`nagapasha/stages/stage11_specialist.py`)
- `run_specialist(near_misses, runner, timeout)` — adaptive escalation
- Heuristic analysis: groups by parameter, checks for consistent status changes, response time spikes, error signatures
- LLM enrichment via Specialist prompt when runner available
- Output: list of verdicts (confirmed/inconclusive with evidence and recommendations)

### Reporting (`nagapasha/stages/stage12_reporting.py`)
- `Report` class — findings, summary, metadata
- `add_finding()` — parameter, attack_class, payload, evidence, confidence, wstg_reference, remediation
- `to_json()` / `to_markdown()` — dual format output
- `save(output_dir)` — writes JSON + markdown files
- Default remediation map for: sql_injection, xss, lfi, idor, ssrf, path_traversal, command_injection, xxe, generic_injection

---

## Phase 4 — Dashboard (FastAPI + WebSocket)

### Dashboard Package (`dashboard/`)

#### Events (`dashboard/events.py`)
- `EventBus` — pub/sub pattern for live updates
- `subscribe(event_type, callback)` — register listeners
- `publish(event_type, data)` — dispatch to subscribers
- `unsubscribe(event_type, callback)` — remove listeners
- `clear(event_type)` — clear listeners (specific or all)
- Error isolation: bad subscribers don't break the bus

#### Active Runs (`dashboard/runs.py`)
- `ActiveRun` — live execution state dataclass
  - Fields: engagement_id, status, loop, payload_count, total_fired, hits, near_misses, no_diff, rate_limit_pps, rate_limit_burst, jwt_expires_at, findings
  - `to_dict()` — JSON serialization for WebSocket pushes
- `ActiveRuns` — in-memory tracker with pause/resume/kill control
  - `start()`, `get()`, `list()` — basic CRUD
  - `pause()`, `resume()` — control PayloadLoop via asyncio.Event
  - `kill()` — signal loop to stop
  - `complete()` — update stats on completion
  - `add_finding()` — append to findings list
  - `remove()` — cleanup after loop finishes

#### REST API (`dashboard/api.py`)
- `GET /api/engagements` — list all engagements from SQLite
- `GET /api/engagements/{id}` — get single engagement
- `POST /api/engagements` — create new engagement
- `GET /api/engagements/{id}/findings` — list findings for engagement
- `GET /api/live/{id}` — get live execution state
- Shared `EngagementStore` instance for cross-request persistence

#### WebSocket (`dashboard/live.py`)
- `WebSocket /ws/{engagement_id}` — bidirectional live updates
- On connect: push initial status + findings
- On message: parse `{"action": "pause"|"resume"|"kill"}`, execute on ActiveRuns
- On disconnect: unsubscribe from events
- Event bus integration: subscribers receive push updates

#### FastAPI App (`dashboard/app.py`)
- CORS middleware (allow all origins for development)
- Static file mounting at `/static/`
- CLI entry point: `run_dashboard(host, port)` via uvicorn

#### CLI Command (`nagapasha/cli.py`)
- `nagapasha dashboard` — starts FastAPI server on `http://0.0.0.0:8000`
- Options: `--host`, `--port`

### Frontend (`dashboard/static/`)

#### HTML (`dashboard/static/index.html`)
- New Engagement form: target URL, method, notes
- Engagement list: clickable items to connect to live run
- Live Run detail:
  - Stat cards: status, requests fired, hits, near-misses, payloads
  - Progress bar: percentage fill with animated transition
  - Action buttons: pause, resume, kill
  - Findings feed: confirmed (red) / near-miss (amber) cards

#### CSS (`dashboard/static/css/dashboard.css`)
- Design tokens from raw-plan.md §8:
  - Fonts: Inter (400/500 weights), SF Mono / JetBrains Mono for code
  - Surfaces: flat fills, `--surface-page: #ffffff`, `--surface-card: #f5f5f4`
  - Semantic colors:
    - `--danger-bg: #fcebeb`, `--danger-text: #791f1f`, `--danger-icon: #a32d2d`
    - `--warning-bg: #faeeda`, `--warning-text: #633806`, `--warning-icon: #854f0b`
    - `--success-bg: #eaf5ec`, `--success-text: #1a6b3a`, `--success-icon: #2d8a4e`
  - Dark mode via `prefers-color-scheme: dark`
- Responsive grid for stat cards
- Tabler Icons integration

#### JavaScript (`dashboard/static/js/live-run.js`)
- WebSocket connection management
- Form submission to create engagements
- Real-time stats update from WebSocket messages
- Finding rendering with semantic styling
- Action button handlers (pause/resume/kill)
- Utility functions: `escapeHtml()`, `formatDateTime()`

### PayloadLoop Modifications (`nagapasha/engine/payload_loop.py`)
- Added pause/resume support:
  - `_paused: bool` — pause state
  - `_resume_event: asyncio.Event` — controls pause/resume
  - `_paused_idx: int` — index where paused (for resume)
- `pause()` — clear resume event, set paused flag
- `resume()` — set resume event, clear paused flag
- `kill_and_reset()` — kill loop and reset pause state
- In `run()` — check pause state between payload iterations

### Database Schema (`nagapasha/db/schema.py`)
- Added `check_same_thread=False` for multi-threaded access
- Extended with `get_engagements()`, `update_engagement_status()` (from Phase 4 plan)

---

## Phase 5 — Hardening & Polish

### Payload Loop Enhancements (`nagapasha/engine/payload_loop.py`)
- **Batch firing**: `batch_size` parameter enables concurrent payload execution via `asyncio.gather`
- **Checkpoint/resume**: `save_checkpoint(path)` and `load_checkpoint(path)` for interrupted run recovery
- Stats saved: `total_fired`, `hits`, `near_misses`, `no_diff`, `request_count`, `paused`, `killed`

### Payload Deduplication (`nagapasha/engine/dedup.py`)
- `deduplicate_payloads(payloads)` — hash-based dedup on (parameter_name, parameter_location, payload)
- `deduplication_stats(original_count, deduplicated_count)` — reduction metrics

### Dry-Run Mode (`nagapasha/engine/dry_run.py`)
- `DryRunRunner` — simulates HTTP requests without sending
- Logs all would-be requests with method, URL, headers, body
- `get_logged_requests()` returns list of logged request dicts
- Used during `--dry-run` mode for safe inspection

### Report Output Formats (`nagapasha/stages/stage12_reporting.py`)
- `to_sarif()` — SARIF 2.1.0 format with unique rules dedup
- `to_junit()` — JUnit XML format for CI/CD integration
- `to_html()` — HTML report with findings table and semantic styling
- `save(output_dir, format="all")` — writes multiple formats at once
- Default remediation map: sql_injection, xss, lfi, idor, ssrf, path_traversal, command_injection, xxe

### ClaudeRunner Enhancements (`nagapasha/llm/runner.py`)
- **Retry with exponential backoff**: `retry_max=3`, `retry_backoff=2.0`
- **Token tracking**: `token_tracker` dict accumulates input/output tokens per stage
- `call_count` property tracks total invocations
- `last_tokens` property for recent token usage
- `reset_stats()` to clear counters between runs

### Request Signing (`nagapasha/security/signing.py`)
- `RequestSigner` — HMAC-SHA256 request signing
- `sign_request()` — adds signature + timestamp to request data
- `verify_signature()` — constant-time HMAC verification
- `generate_secret_key()` — random hex-encoded key generation
- Configurable header name and algorithm

### Exfiltration Prevention (`nagapasha/security/exfil.py`)
- `HostAllowlist` — validates URLs against allowed hosts/domains
- Subdomain matching, IP CIDR range matching, localhost control
- Suspicious character detection in URLs
- Blocked event logging with reason tracking
- `add_allowed()` / `remove_allowed()` for dynamic management

### Template Support (`nagapasha/engine/template.py`)
- `TemplateManager` — create, load, list, delete, validate engagement templates
- JSON schema with versioning, method validation, body_type validation
- `create_from_curl()` — parse curl command into template
- `get_curl_command()` — reverse: template back to curl
- Schema: name, target_url, method, headers, cookies, body, body_type, fuzz_preferences

### CLI Updates (`nagapasha/cli.py`)
- **`nagapasha dashboard`**: Start FastAPI server (Phase 4)
- **`nagapasha cicd`**: Non-interactive CI/CD with severity gating, SARIF output
- **`nagapasha template`**: create/load/list engagement templates
- **`nagapasha full` flags**: `--batch-size`, `--output-format`, `--dry-run`, `--max-requests`
- Scope confirmation for CI/CD runs (auto-confirm)

### Security Package (`nagapasha/security/`)
- `signing.py` — HMAC request signing
- `exfil.py` — Host allowlist exfiltration prevention

---

## Phase 6 — Outcome-Based Detection Engine & Technique Categories

This phase shifts the center of gravity from "does the tool know this string" to "can the tool notice that something changed." Payloads are generated by technique category with dialect variants, and detection is based on response outcomes, not memorized bypass strings.

### Bug Fixes (Phase 0–1)

**Payload Loop — `nagapasha/engine/payload_loop.py`**
- Fixed `candidate.raw_body` NameError in `_build_request_with_payload` — added `raw_body: bool = False` keyword parameter, fixed body_json branch condition, updated call site to pass `raw_body=candidate.raw_body`.
- Added error tracking to `PayloadResult`: `error: Optional[str]` field, `"INTERNAL-ERROR"` classification, evidence field, exception logging with `logger.warning(...)`, error passed through to result dicts.
- CLI `_on_result()` now prints INTERNAL-ERROR in red before other classifications.

### Outcome Detection (`nagapasha/engine/diff.py`)

- **Auth-flip detection**: When baseline status is 401/403 and the payload response is 2xx, set `delta.is_confirmed_hit = True` with `"auth-flip: 401 → 200"` detail. Confidence 0.95.
- **Auth-artifact detection**: New `Set-Cookie` header not in baseline → signal. JWT-shaped token in body (three base64url segments separated by dots) → signal. Generic session field names (`token`, `access_token`, `session_id`, `api_key`, `refresh_token`, `id_token`) in JSON response → signal. Confidence 0.90.
- **Broadened error signatures**: Extended from SQL-only to cover:
  - NoSQL drivers: `PymongoError`, `MongoServerError`, `DriverError`, `RedisError`
  - Template engines: `TemplateSyntaxError`, `TemplateAssertionError`, `TemplateNotFound`, `jinja2.Environment`
  - Shell/command injection: `sh`, `bash`, `/bin/`, `permission denied`, `file does not exist`, `include_path`, `allow_url_include`
- Added `has_new_auth_artifact: bool = False` to `ResponseDelta` dataclass and `to_dict()`.

### Triage Updates (`nagapasha/engine/triage.py`)

- Auth-flip → HIT (confidence 0.95) when `delta.is_confirmed_hit` and `delta_details` contains "auth-flip".
- Auth-artifact → HIT (confidence 0.90) when `delta.has_new_auth_artifact`.
- Status code delta ≥100 → HIT (confidence 0.80).
- Near-miss signals preserved: status delta, content-length delta, response time spike.
- Body-changed without clear signal → ambiguous (confidence 0.30).

### Differential Pair Detection (`nagapasha/engine/differential.py`) — NEW

- `DeltaSignal` dataclass: `detected`, `description`, `significance`, `delta_details`.
- `run_differential_pair(true_body, false_body, true_status, false_status, true_headers, false_headers)` — compares true-condition vs false-condition responses against each other (not against baseline).
- Checks: status code difference (0.80), body hash difference (0.50), header set difference (0.40).
- Technique-category tagged payloads produce paired variants; differential checks whether the two logically-opposite payloads produced different responses — dialect-agnostic (SQL boolean, NoSQL `$ne`/`$eq`, template truthy/falsy).

### Timing-Anomaly Detection (`nagapasha/engine/timing_anomaly.py`) — NEW

- `TimingMonitor` class with rolling window (`deque`, max 10 samples).
- `record_baseline(elapsed)` — records non-payload response times.
- `check(payload_elapsed)` — flags anomaly if >3x baseline AND >2x rolling mean.
- Returns `TimingCheck` with `anomalous`, `delay_magnitude`, `baseline_avg`, `current_elapsed`.
- Detects blind/time-based injection by side effect (executing a delay) rather than by payload string.

### Technique Categories (`nagapasha/utils/technique_categories.py`) — NEW

- `TECHNIQUE_CATEGORIES` dict with 6 categories, each with SQL/NoSQL/template dialect variants:
  - `comment_terminator`: Break out of string context (`'--`, `" //`, `${`, `[%`)
  - `tautology`: Always-true conditions (`' OR 1=1--`, `{"$ne": null}`, `{{7*7}}`)
  - `boolean_differential`: Paired true/false for differential detection (SQL: `AND 1=1`/`AND 1=2`, NoSQL: `$ne` null/$eq "")
  - `time_based_blind`: Delay injection (`SLEEP(5)`, `BENCHMARK(...)`, JS `sleep()`)
  - `union_based`: Result set exfiltration
  - `stacked_query`: Arbitrary query execution (`; DROP TABLE`, `; SELECT *`)
- `CATEGORY_TARGET_LOCATIONS` — maps categories to effective parameter locations.
- `AUTH_PRIORITY_CATEGORIES` — `("tautology", "boolean_differential")` for auth endpoints.

### Auth-Endpoint Detection (`nagapasha/utils/auth_detect.py`) — NEW

- `detect_auth_endpoint(request_model)` — URL path matching (login, signin, register, signup, auth, password-reset, forgot-password, token, oauth, callback) + body content co-occurrence (email/username-like AND password-like fields).

### Request Model (`nagapasha/models/request_model.py`)

- Added `is_auth_endpoint: bool = False` field.

### CLI (`nagapasha/cli.py`)

- Auto-detects auth endpoints in `full` and `cicd` commands, sets `req.is_auth_endpoint`.
- Refactored `_build_payload_candidates()` to use `_build_technique_category_payloads()`:
  - For auth endpoints with credential fields (email, username, login, user), prioritizes tautology and boolean_differential categories.
  - Generates dialect variants (SQL + NoSQL + template) based on confirmed tech stack.
  - For boolean_differential, generates both true and false condition payloads.
  - For time_based_blind, marks payloads with probe_variant hint.
- Report softening: when `is_auth_endpoint` and 0 hits, prints yellow note that testing does not prove absence of vulnerabilities.

---

## Test Coverage

| Module | Tests |
|--------|-------|
| curl_parser | 35 tests |
| rate_limiter | 11 tests |
| baseline | 11 tests |
| diff | 9 tests |
| jwt_watchdog | 19 tests |
| script_generator | 9 tests |
| payload_loop | 14 tests |
| stage03_targeting | 5 tests |
| strategist | 12 tests |
| fitter | 12 tests |
| librarian | 5 tests |
| triage | 7 tests |
| specialist | 7 tests |
| reporting | 6 tests |
| **dashboard/events** | 8 tests |
| **dashboard/runs** | 13 tests |
| **dashboard/api** | 7 tests |
| **dashboard/ws** | 5 tests |
| dedup | 12 tests |
| signing | 8 tests |
| exfil | 14 tests |
| dry_run | 6 tests |
| template | 16 tests |
| claude_runner | 9 tests |
| batch_firing | 7 tests |
| output_formats | 16 tests |
| differential | 8 tests |
| timing_anomaly | 7 tests |
| auth_detect | 10 tests |
| technique_categories | 12 tests |
| outcome_detection | 10 tests |
| **Total** | **392 tests, all passing** |
