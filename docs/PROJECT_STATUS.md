# Project status — v0.7.5 (latest)

## Milestone 1: AST analyzer

- [x] Project package and CLI skeleton
- [x] AST parser and syntax-error reporting
- [x] Common finding model
- [x] Five custom security rules
- [x] Exception-handling quality warning
- [x] Evidence masking for likely hardcoded secrets
- [x] JSON serialization
- [x] Safe and insecure sample files
- [x] Positive, negative, parser, and non-execution tests

## Milestone 2: Bandit integration

- [x] Bandit subprocess adapter
- [x] Fixed argument list and `shell=False`
- [x] Scanner timeout and temporary-file cleanup
- [x] Bandit JSON parsing and finding normalization
- [x] CWE, severity, confidence, and line-number mapping
- [x] Secret masking in Bandit evidence
- [x] Related Bandit detections attached to matching custom findings
- [x] Graceful warning when Bandit is unavailable
- [x] CLI option to skip Bandit with `--no-bandit`

## Milestone 3: Flask API and SQLite

- [x] Flask application factory and local-only development server
- [x] Health-check and root information endpoints
- [x] File-upload and pasted-source scan endpoint
- [x] `.py` extension, filename, UTF-8, and source-size validation
- [x] Optional Bandit execution per scan
- [x] SQLite scan history and finding persistence
- [x] Scan list and scan detail endpoints
- [x] JSON and HTML report downloads
- [x] Source code is not stored as a complete file
- [x] SQLite migration for the v0.5 fields

## Milestone 4: React + Vite dashboard

- [x] React single-page dashboard with responsive layout
- [x] Vite development server proxying `/api` to Flask on port 5000
- [x] Backend connection status and health check
- [x] Python `.py` upload and pasted-source submission
- [x] Optional Bandit toggle
- [x] Scan summary cards and severity distribution
- [x] Findings list with severity filter and text search
- [x] Finding detail panel with evidence, confidence, CWE, and recommendation
- [x] Scan history list and detail reopening
- [x] JSON and HTML report download links
- [x] Source Context display masking

## Milestone 5: Advanced static analysis (v0.5.0)

- [x] Optional mypy adapter with isolated config, timeout, and fixed subprocess arguments
- [x] Type diagnostics stored and displayed separately from security findings
- [x] CLI `--mypy` option
- [x] ZIP archive upload and in-memory Python entry scanning
- [x] ZIP path traversal, symlink, encrypted entry, duplicate path, file count, and size checks
- [x] Multiple-file findings retain archive-relative paths
- [x] Cross-scanner duplicates preserve related Bandit rule metadata
- [x] SQLite stores type-check summary, file list, file errors, and duplicate count
- [x] HTML/JSON reports include type-check and multi-file information
- [x] Synthetic labeled evaluation dataset and metrics utility

## Validation performed in the build environment

- Python compilation: completed successfully for project and test modules.
- Core test selection: 38 tests passed (`parser`, `rules`, `analyzer`, `mypy adapter`, `evaluation`, and `storage/report` tests).
- ZIP validation smoke test: accepted a valid multi-file archive and rejected a traversal entry without extracting files.
- Frontend JSX syntax: `App.jsx` and `main.jsx` transpile without syntax diagnostics; Vite production build was not run.
- Synthetic evaluation command: completed for 10 hand-labeled samples. It currently reports 5 TP, 5 TN, and zero FP/FN on this small regression set. These values are not real-world accuracy.
- Full Flask API tests and frontend production build could not be executed in this build environment because Flask, Werkzeug, Bandit, mypy, and npm dependencies are not installed and package-registry network access is unavailable.

## Required local verification on the user's Mac

1. Install the new `requirements.txt` into the v0.5 virtual environment.
2. Run the complete `pytest` suite, including Flask/ZIP upload tests.
3. Run `python -m security_analyzer.evaluation`.
4. Run a `.py` scan with Bandit enabled and mypy enabled.
5. Upload a ZIP containing multiple `.py` files and confirm the findings retain each archive-relative path.
6. Try a ZIP with a `../` entry and confirm it is rejected.
7. Enable the mypy toggle in the dashboard and confirm type issues appear in the separate Type Safety panel.
8. Run `npm install` and `npm run build` in `frontend/`.

## Remaining project work

- [x] AI explanation adapter with explicit consent and redaction
- [ ] Verify English-only structured AI output on the user's NVIDIA account and browser
- [ ] Architecture and flowchart graphics
- [ ] Expand the labeled evaluation dataset beyond the current small regression set
- [ ] Final technical report and presentation
- [ ] Screenshots and demonstration video


## Milestone 6: Finding explanations (v0.6.3)

- [x] Local rule-based explanation fallback works without an external API key
- [x] Optional NVIDIA Nemotron 3.5 Lightning Chat Completions adapter
- [x] Explicit UI confirmation before any external AI request
- [x] Backend rejects external explanation requests without consent
- [x] Only selected finding metadata and redacted evidence are sent; original source is excluded
- [x] API key remains server-side and is read from `NVIDIA_API_KEY`
- [x] NVIDIA Chat Completions request sends only selected finding metadata and redacted evidence
- [x] Explanation tests cover local mode, consent enforcement, redaction, and provider response parsing

## v0.6.3 validation in the build environment

- Python compileall: passed.
- Core test selection excluding Flask API tests: 45 passed.
- Flask API tests could not be collected in this offline build environment because Flask is not installed and package-registry access is unavailable.
- Vite production build could not be run because frontend npm packages are not installed in this environment.
- AI explanation tests assert the English-only prompt and the four required section headings.
- The user's live NVIDIA API request was already verified in the previous version; the updated prompt and frontend formatting still require one browser-side confirmation on the user's Mac.



## v0.6.3 NVIDIA response-budget correction

The direct NVIDIA endpoint check confirmed that the pinned model ID is valid and the hosted endpoint responds. The first test returned `finish_reason=length`, `content=null`, and 160 reasoning tokens because Nemotron reasoning was enabled by default and consumed the small 160-token output budget. The NVIDIA adapter now disables thinking for concise finding explanations using `chat_template_kwargs: {"enable_thinking": false}`, raises `max_tokens` to 1024, and avoids setting both `temperature` and `top_p` in the same request. Unit coverage asserts these request parameters. This corrects the output-budget issue; a live end-to-end call from the user's NVIDIA key remains to be verified on the user's Mac.


## v0.6.3 AI explanation readability update

- NVIDIA system prompt now requires English-only output with four fixed headings: What it means, Why it matters, Safer approach, and Safe example.
- The React dashboard parses those sections and renders them as separate blocks; safe examples use a monospace code panel.
- AI explanation text, headings, button, provider label, and disclaimer have larger targeted typography. Other dashboard styling is unchanged.
- Automated AI tests assert the English-only prompt and expected section contract.


## v0.7.2 — Security Assistant

- Added a floating scan-aware chat widget with a one-click current-scan review prompt.
- Added a backend chat endpoint that accepts only a scan ID, bounded natural-language question, short bounded history, and optional finding reference.
- Context is built server-side from compact masked finding metadata. Original source, file paths, raw evidence, API keys, and environment variables are excluded.
- Added deterministic pre-provider guards for scope, prompt injection, likely secrets, pasted source code, harmful malware requests, message size, and request rate.
- NVIDIA requests require per-message consent; no-key mode uses deterministic local guidance.
- Added output checks for secret-like strings and dangerous or malformed fenced Python examples.
- Chat history remains in browser memory and is not stored in SQLite.


## v0.7.2 build validation

- Python compile checks: passed for all project and test modules.
- Core Python tests excluding Flask API tests: 61 passed.
- Dedicated assistant tests cover scope rejection, prompt-injection rejection, secret detection, source-code paste rejection, input length, bounded history, explicit consent, local-only fallback, NVIDIA payload minimization, and unsafe output-code rejection.
- React JSX parser diagnostics: 0.
- CSS brace-balance check: passed.
- Flask route tests and Vite production build were not run in this offline build environment because Flask is not installed and frontend npm packages are not installed. Run the complete test suite and `npm run build` on the user's Mac before treating the release as fully verified.


## v0.7.2 update
- Added a dependency-free, safe Markdown renderer for assistant chat responses.
- Ordered/unordered lists, paragraphs, headings, inline code, and fenced code blocks render as React text nodes; raw HTML is not interpreted.
- Added Node built-in regression tests for the Markdown parser.


## v0.7.2 — Local assistant fallback intent fix

- Fixed an intent-classification collision where the word "review" forced scan-summary mode even when the user had selected a specific finding.
- Finding-specific requests now use deterministic rule guidance; explicit scan/overall/summary/priority requests continue to use scan-summary guidance.
- Added regression tests for both branches, including the exact no-NVIDIA-key API scenario reported during macOS validation.


## v0.7.4 scope correction

- The assistant now accepts defensive application-security questions beyond Python, including conceptual comparisons of SQL injection and command injection.
- Prompt-injection, secret detection, harmful-request rejection, consent, message-length, and output validation controls remain enabled.
- Added regression tests for the previously rejected SQL injection vs. command injection question and for the NVIDIA system prompt scope.


## v0.7.5 — NVIDIA provider resilience

- Added structured provider errors carrying a safe local HTTP status and optional bounded `Retry-After` value.
- NVIDIA 429 maps to local HTTP 429; a valid `Retry-After` header is forwarded.
- Provider timeout maps to HTTP 504; upstream 5xx and connection failures map to HTTP 503; invalid provider credentials/model/request failures remain HTTP 502.
- Provider response bodies and secret-bearing details are not exposed to the browser.
- No automatic retries are performed for generation POSTs to avoid duplicate token usage when a request may have completed before a network timeout.
- Added mocked tests for 429, invalid Retry-After, timeout, connection failure, upstream 503, and Flask route status/header propagation.

## v0.7.5 validation in the build environment

- Python compilation: passed.
- Non-Flask Python tests: 71 passed.
- Frontend Markdown tests: 5 passed.
- Flask route tests could not be executed in this build environment because Flask is unavailable and package registry access is blocked. Run the complete test suite on macOS; expected count is 105 tests (71 non-Flask tests and 34 Flask route tests).
