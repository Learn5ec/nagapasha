# nagapasha — Adaptive AI-Powered Intruder

A multi-agent, self-scoping fuzzing tool that takes a single curl request and turns it into a targeted, rate-limit-aware, tech-stack-aware attack suite — with enterprise-grade authorization gates, supply-chain safety, and evidence integrity.

> **Disclaimer:** This tool is for authorized security testing only. Users are solely responsible for ensuring they have proper authorization before running scans against any target. The authors are not liable for misuse. Use at your own risk.

## 🎯 What's New in v2

- **Authorization Gates (Stage 0)**: Signed engagement contexts with scope validation and kill switch
- **Payload Provenance (Stage 2.5)**: Source vetting with checksum verification
- **Destructive Payload Confirmation (Stage 8.5)**: TTY-aware safety gates with constrained probes
- **Continuous Recalibration (Stage 9.5)**: WAF monitoring and baseline drift detection
- **Evidence Integrity (Stage 13)**: SHA256 hashing, PII redaction, and engagement ID stamping
- **Idempotent Resume**: Identity hashing for payload deduplication
- **LLM Input Hygiene**: Evidence validation before HIT escalation

## Features

### Core Engine
- **cURL Ingestion**: Parse any curl command into a structured request model
- **Recon**: Auth validation, JWT detection/expiry monitoring, baseline capture, rate-limit calibration
- **Diff Engine**: Detect status changes, content-length anomalies, response time spikes, payload reflection, error signatures
- **Token Bucket Rate Limiter**: Accurate rate limiting with 429 penalty
- **SQLite Storage**: Engagements, findings, audit logs, LLM call tracking

### Multi-Agent Pipeline (Phases 1–3)
- **Strategist** (LLM): Vulnerability surface analysis and attack candidate generation
- **Librarian** (offline KB + LLM + MCP): Payload sourcing with local knowledge base and optional Brave Search MCP fallback
- **Fitter** (heuristic/LLM): Payload placement, encoding, and glue decisions
- **Specialist** (LLM): Adaptive near-miss analysis and escalation with machine-verifiable evidence
- **Triage**: Heuristic response classification (HIT / NEAR-MISS / no-diff)
- **Reporting**: JSON, markdown, SARIF, JUnit XML, and HTML output formats

### MCP Web Search (Phase 5+)
- **Brave Search Integration**: Runtime web search for payloads, wordlists, and technique documentation
- **Temp Downloads**: Automatic download of `.txt`, `.zip`, `.tar.gz` files to temp directory
- **24-Hour TTL Cleanup**: Background cleanup task deletes temp files after 24 hours
- **Manifest Tracking**: JSON manifest tracks all downloaded files with timestamps
- **Offline-First**: Searches local KB first, falls back to MCP when insufficient

### Dashboard (Phase 4)
- **FastAPI + WebSocket**: Live run updates with pause/resume/kill controls
- **Real-time UI**: Stat cards, progress bar, findings feed with semantic colors
- **REST API**: Engagement CRUD, findings listing, live status endpoints
- **Design Tokens**: Flat fills, Inter font, dark mode, Tabler Icons

### Hardening & Polish (Phase 5)
- **Batch Firing**: Concurrent payload execution via `--batch-size`
- **Checkpoint/Resume**: Save and resume interrupted runs
- **Payload Deduplication**: Hash-based dedup on identity (param + location + payload)
- **Dry-Run Mode**: Log requests without sending (`--dry-run`)
- **CI/CD Command**: `nagapasha cicd` with severity gating and SARIF output
- **Template Support**: `nagapasha template create/load/list` for reusable profiles
- **HMAC Request Signing**: Sign outgoing requests for test integrity
- **Exfiltration Prevention**: Host allowlist blocks unauthorized destinations
- **ClaudeRunner Enhancements**: Retry with exponential backoff, token usage tracking

### v2 Enterprise Features
- **Authorization Gates**: Scope validation, kill switch, and engagement context signing
- **Supply-Chain Safety**: Payload source vetting with checksum verification
- **Destructive Payload Safety**: Interactive confirmation gates with probe variants
- **Continuous Recalibration**: WAF monitoring, baseline drift detection, rolling control requests
- **Evidence Integrity**: SHA256 hashing, PII redaction, engagement ID stamping
- **Retention Policy**: Automatic cleanup of expired engagement data
- **LLM Input Hygiene**: Evidence validation before HIT escalation

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

### Interactive Setup

Run the setup wizard to configure your environment:

```bash
python setup.py
```

This will guide you through:
- API key configuration (Anthropic, Brave Search)
- Security settings (HMAC key, rate limits)
- Performance tuning (batch size, max requests)
- Generate `.env`, `.gitignore`, and `README.md`

### Manual Configuration

Copy the example environment file and fill in your keys:

```bash
cp .env.example .env
# Edit .env with your API keys
```

### Parse a curl command

```bash
nagapasha parse "curl -X GET 'https://example.com/api/users?page=1&limit=10' -H 'Authorization: Bearer eyJ...' -H 'X-User-Id: 42'"
```

### Initialize engagement (Stage 0)

Create a signed engagement context from a Rules of Engagement (ROE) file:

```bash
nagapasha init --roe roe.yaml --output test.ctx
```

The ROE file defines:
- Host allowlist/denylist
- Time window
- Allowed HTTP methods
- Excluded attack classes
- Authorized tester

### Run recon (requires .ctx)

```bash
nagapasha recon --curl-file req.txt --engagement test.ctx
```

### Generate execution script

```bash
nagapasha generate --curl-file req.txt --engagement test.ctx
```

### Execute generated script

```bash
nagapasha run --script scripts/engagements/<id>/run_payloads.py
```

### Full pipeline (parse → recon → targeting → generate → execute)

```bash
nagapasha full "curl -X GET 'https://example.com/api/users?page=1'" \
  --engagement test.ctx
```

### Full pipeline with options

```bash
nagapasha full "curl -X GET 'https://example.com/api/users?page=1'" \
  --batch-size 4 \
  --output-format all \
  --max-requests 500 \
  --dry-run \
  --engagement test.ctx
```

### Dry-run mode (safe preview)

```bash
nagapasha full "curl -X GET 'https://example.com/api'" \
  --dry-run --engagement test.ctx
```

Output shows what would fire without sending:

```
[Dry run] Would fire:
  [body_json] id=42 → sql_injection (destructive=false)
    Payload: ' OR '1'='1--
  [header] X-User-Id=100 → idor (destructive=false)
    Payload: 999999
  [body_json] upload=file.exe → rce (destructive=true) ⚠️
    Payload: sleep(5); cat /etc/passwd
```

### Kill switch (abort)

From a separate terminal:

```bash
nagapasha abort --engagement test.ctx
```

This writes a kill switch file that the running scan polls. Immediate abort on Ctrl-C.

### Check engagement status

```bash
nagapasha status --engagement test.ctx
```

### Dashboard

```bash
nagapasha dashboard --port 8000
# Open http://localhost:8000 in your browser
```

### CI/CD integration

```bash
nagapasha cicd "curl -X POST 'https://api.example.com/users'" \
  --engagement test.ctx \
  --fail-on-severity high \
  --output-format sarif
```

### Templates

```bash
nagapasha template create --name my-api --curl "curl -X POST 'https://api.example.com/data'"
nagapasha template load --name my-api
nagapasha template list
```

### Checkpoint resume

```bash
# Save checkpoint during run, resume later
nagapasha full "curl -X GET 'https://example.com/api'" --batch-size 4
# (after pause/kill)
nagapasha full "curl -X GET 'https://example.com/api'" --batch-size 4 --resume checkpoint.json
```

## Architecture

### Phases (Implemented)

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Authorization gate (engagement context, scope, kill switch) | ✅ |
| 1 | cURL parser, recon, baseline capture, rate-limit calibration | ✅ |
| 2 | Multi-agent targeting (Strategist, Librarian, Fitter) | ✅ |
| 3 | Triage, Specialist, Reporting | ✅ |
| 4 | Dashboard (FastAPI + WebSocket) | ✅ |
| 5 | Batch firing, checkpoint, dedup, dry-run, CI/CD | ✅ |
| 2.5 | Payload provenance vetting | ✅ |
| 8.5 | Destructive payload confirmation | ✅ |
| 9.5 | Continuous recalibration | ✅ |
| 13 | Evidence integrity & redaction | ✅ |

### CLI Subcommands

```
nagapasha init      # Stage 0: Create signed EngagementContext from ROE
nagapasha recon     # Stages 1-2: Parse + Recon (requires .ctx)
nagapasha run       # Stages 3, 5, 7, 8, 9-11: Execute (requires .ctx, optional --resume)
nagapasha report    # Stages 12-13: Generate reports (requires .ctx)
nagapasha abort     # Kill switch (requires .ctx)
nagapasha status    # Progress inspection (requires .ctx)
```

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | Completed, no HITs |
| 1 | Completed with HITs |
| 2 | Aborted (kill switch or Ctrl-C) |
| 3 | Configuration error |
| 4 | Runtime error |

## Project Structure

```
nagapasha/
├── nagapasha/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                    # Typer CLI (init, recon, run, report, abort, status)
│   ├── engagement.py             # NEW: EngagementContext with signing & scope
│   ├── scope.py                  # NEW: ScopeChecker middleware
│   ├── models/
│   │   └── request_model.py      # Shared RequestModel dataclass
│   ├── stages/
│   │   ├── stage01_parse.py      # cURL parser
│   │   ├── stage02_recon.py      # Recon orchestrator
│   │   ├── stage03_targeting.py  # Human parameter selection
│   │   ├── stage05_strategist.py # LLM Strategist agent
│   │   ├── stage07_librarian.py  # Payload KB sourcing (with provenance)
│   │   ├── stage08_fitter.py     # Placement & encoding
│   │   ├── stage11_specialist.py # Adaptive escalation (with evidence validation)
│   │   └── stage12_reporting.py  # Report generation (with redaction & hashing)
│   ├── engine/
│   │   ├── runner.py             # Async HTTP runner (httpx)
│   │   ├── dry_run.py            # Dry-run request logger
│   │   ├── rate_limiter.py       # Token bucket rate limiter
│   │   ├── jwt_watchdog.py       # JWT detection & expiry
│   │   ├── baseline.py           # Baseline capture
│   │   ├── diff.py               # Response diffing
│   │   ├── payload_loop.py       # Payload execution loop (batch, checkpoint, recalibration)
│   │   ├── recalibration.py      # NEW: WAF monitoring & baseline drift
│   │   ├── dedup.py              # Payload deduplication (identity_hash)
│   │   ├── template.py           # Engagement template manager
│   │   └── triage.py             # Heuristic response triage
│   ├── security/
│   │   ├── signing.py            # HMAC request signing
│   │   ├── exfil.py              # Host allowlist exfiltration prevention
│   │   └── redact.py             # NEW: PII/secret redaction
│   ├── db/
│   │   └── schema.py             # SQLite storage (with retention policy)
│   ├── llm/
│   │   ├── runner.py             # Claude CLI subprocess (retry + token tracking)
│   │   ├── contracts.py          # JSON contracts
│   │   └── prompts/              # System prompt templates (with hygiene)
│   └── utils/
│       ├── confirm.py            # NEW: Destructive payload confirmation
│       ├── payload_provenance.py # NEW: Source vetting
│       ├── temp_downloads.py     # Safe file extraction
│       ├── paths.py              # NEW: Path utilities
│       ├── config.py             # NEW: Configuration management
│       ├── scope_guard.py        # Authorization & kill switch
│       └── notifications.py      # OS-native + Slack
├── dashboard/
│   ├── __init__.py               # Module-scoped EventBus + ActiveRuns singletons
│   ├── app.py                    # FastAPI app + CLI entry
│   ├── api.py                    # REST endpoints
│   ├── live.py                   # WebSocket endpoint
│   ├── events.py                 # EventBus pub/sub
│   ├── runs.py                   # ActiveRuns tracker
│   └── static/
│       ├── index.html            # Live Run UI
│       ├── css/dashboard.css     # Design tokens, dark mode
│       └── js/live-run.js        # WebSocket + UI logic
├── docs/
│   ├── raw-plan.md               # Original specification
│   ├── current-implementation.md # What is built
│   └── future-implementation.md  # What's planned
├── tests/                        # 383 tests, all passing
├── pyproject.toml
├── setup.py                      # Interactive setup wizard
├── .env.example                  # Example environment file
└── README.md
```

## Testing

```bash
pytest tests/ -v
# 383 tests, all passing
```

## Guardrails

- **Explicit scope confirmation** before first live request
- **Hard cap** on total request volume per run (default: 10,000)
- **Kill switch** (file-based, cross-process abort)
- **Audit logging** of all request/response pairs
- **Evidence hashing** (SHA256) for chain of custody
- **PII redaction** before storage
- **Engagement ID stamping** on all artifacts
- **Retention policy** with automatic cleanup

## Security Considerations

- **Never** run against unauthenticated targets
- **Always** use `--dry-run` first to preview payload execution
- **Enable** destructive payload confirmation in interactive mode
- **Review** ROE file carefully before `nagapasha init`
- **Monitor** kill switch state during execution
- **Verify** evidence hashes before sharing findings

## License

MIT