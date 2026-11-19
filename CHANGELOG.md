<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

# Changelog

All notable changes to the **Integrated HAST Vulnerability Assessment Model (Intelligent Vulnerability Management Model: SAST & DAST Scanning Integration)** project are documented in this file.

## [2.0.0] - Unreleased

### Added (2.1 — model context on recommendations)

- **dss**: "Rekomendasi sistem" audit events now store the model explanation snapshot (`model_context`: score origin, SHAP reason, review notes, recommended priority, run ID), both when an issue is first recorded and when its recommendation changes. Previously only decision events had it.
- **db**: Alembic revision `0005_recommendation_model_context` backfills existing recommendation events from the DSS run that produced them. The revision is idempotent, and events whose run is missing are left unchanged.
- **test**: 2 tests (new events carry the context; the migration backfills and is idempotent).

### Changed (2.1 — deployment behind Nginx Proxy Manager)

- **deploy**: `docker-compose.yml` targets Nginx Proxy Manager. `api` and `ui` no longer publish host ports. They join an external Docker network (`PROXY_NETWORK`, default `proxy`) shared with the NPM container, under the aliases `hast-api` and `hast-ui`.
- **docs**: The README *Deployment* section gives the NPM *Proxy Host* settings: `hast-ui:8501` with Websockets Support, custom locations `/api` and `/sample-reports` → `hast-api:8000`, and Let's Encrypt SSL. `PUBLIC_API_BASE_URL` is set to `https://<domain>`. `PROXY_NETWORK` is documented in `.env.sample` and `docs/CONFIGURATION.md`.

### Added (2.1 — automatic issue recording)

- **api**: `POST /api/v1/correlation/run` now records the new hybrid session's issues and recommendations in the DSS straight away, when the caller is logged in with the `dss.save_run` permission. The actor is stored in the audit trail.
  - The response gains a `dss` object: `{recorded, issues, run_id}`, or `{recorded: false, reason}` with `not_logged_in`, `not_permitted`, `failed` or `no_pairs`.
  - Recording runs in a savepoint, so a DSS failure never discards the correlation result.
- **ui**: The Korelasi Hybrid tab reports whether issues were recorded. The Dashboard warns when hybrid results exist but no issues are recorded yet.
- **ui**: The login/logout buttons read "Login"/"Logout" (missed by the earlier term replacement).
- **test**: 3 tests with synthetic hybrid scoring (no model artefacts needed).

### Removed (2.1 — Caddy)

- **deploy**: The Caddy reverse proxy was removed (`deploy/Caddyfile` and the `caddy` service with its volumes in `docker-compose.yml`).
  - `api` and `ui` now publish ports 8000 and 8501 directly.
  - `uvicorn` no longer trusts forwarded headers (`--proxy-headers --forwarded-allow-ips "*"`).
  - `HAST_DOMAIN` is no longer used.

  There is no built-in HTTPS any more; put the stack behind the server's own reverse proxy/TLS when it is exposed to the internet.
- **frontend**: An empty `PUBLIC_API_BASE_URL` now falls back to `API_BASE_URL`. Previously an empty value produced relative sample-report links that only worked behind Caddy.

### Changed (2.1 — English technical terms in the UI)

- **ui/api**: Technical terms in user-facing text now use English for familiarity:
  - navigation and accounts: Dashboard, Login/Logout, Username, Password, User, Role, Settings;
  - data and files: Upload, Download, Export, File, Database, Preview, History;
  - security: Scan/Scanner, Severity, False Positive, Audit Trail;
  - DSS workflow: Issue, Due Date, Overdue, Session.

  The review flag "Perlu dicek" is renamed **"Perlu diperiksa"** (badge, metric, filter, CSV column, and the Excel column *Perlu Diperiksa*).
- **db**: Alembic revision `0004_english_payload_keys` rewrites stored JSON that still used Indonesian keys:
  - audit-trail payloads: `konteks_model` and the keys inside it, plus `dari`/`menjadi` diffs;
  - imputation codes in saved DSS runs.

  The revision is idempotent. The legacy-key translation in `repositories/dss.py` was removed, so stored data and code now use English keys only.

  Sentences stay in Indonesian. Code comments and docstrings, page URL paths (`?dasbor`, `/riwayat`, …), widget keys and the `ISU-` issue code are unchanged.
- **api**: The Excel decision export columns are renamed accordingly (`Issue`, `Overdue`, `Due Date (SLA)`, `Session Terakhir`). The research class distribution rows use the key `Severity Level`; the legacy key `Tingkat Keparahan` is still accepted on input.

### Fixed (2.1 — DSS review)

- **ui**: The follow-up form on *Prioritas Perbaikan* now sends only the fields the user's role may change. Developers no longer get a 403 when updating progress, and saving a status no longer turns an unassessed business impact or effort into an explicit "Sedang". Both fields gain a "Belum dinilai" option.
- **dss**: A stored SLA due date now tightens when a re-rank escalates the recommendation. It is never loosened, and never changed when an analyst set the due date or priority, or when the issue is closed.
- **api**: `POST /api/v1/dss/rank` rejects `persist=true` combined with what-if overrides (`weights`, `escalation_rate`, or a `method` that differs from the config), so simulations cannot replace stored recommendations.
- **dss**: "Business impact not assessed" is no longer shown when the value comes from an `asset_criticality` config rule.
- **test**: 6 new tests in `tests/test_dss_api.py`.

### Added (2.1 — dashboard)

- **ui**: New default page **Dasbor**:
  - KPI tiles: open, P1 open, overdue, due soon, unassigned, closed, agreement with recommendation, plus a "Perlu dicek" warning;
  - charts: open issues by priority × status, severity of the latest scan per scanner, top CWE, workload per owner, High + Critical trend across sessions;
  - an upcoming-deadline table.

  Every chart has a "Lihat data" table view.
- **api**: `GET /api/v1/dashboard` (read-only summary). Aggregation is pure logic in `backend/dss/dashboard.py`; per-batch statistics come from `history_repo.batch_stats`.
- **test**: `tests/test_dashboard.py` (4 tests).

### Changed (2.1 — code language standard)

- **code**: All code comments and docstrings were rewritten in standard Indonesian. Docstrings use `Parameter:` / `Mengembalikan:` sections; tool metadata is kept as is.
- **code**: All identifiers are now in English:
  - training-script variables (`accuracy_value`, `confusion_matrix_values`, …) and `get_mode`;
  - 20 black-box test function names (TC codes preserved);
  - internal data keys (`model_context`, `score_origin`, `model_reason`, `review_notes`, `recommended_priority`, `from`/`to`).

  Audit events stored with the old keys were normalised on read until revision `0004_english_payload_keys` rewrote them (see below).
- **fix**: The regex docstring in `sonar_cwe_mapper` is now a raw string, removing a pre-existing `SyntaxWarning`.

### Added (2.1 — SHAP in the DSS)

- **dss**: `backend/dss/explain.py` adds the following per issue:
  - a score chain (SAST, DAST → average → escalation → hybrid);
  - a SHAP text-factor summary (labelled as explaining the model's combined-text prediction, not the hybrid score);
  - a one-line model reason;
  - heuristic "Perlu dicek" flags (near a severity boundary, weak text evidence, or no explanation), configurable in `dss_config.review`.
- **dss**: Decision audit events store a server-side snapshot of the model context at decision time. The Excel export gains the columns *Asal Skor*, *Alasan Model (SHAP)*, and *Perlu Dicek*.
- **frontend**: *Asal skor* tab, "Perlu dicek" badge, metric and filter, and a "considerations" box before the follow-up form. Model context is shown in the decision history.
- **test**: 13 explanation tests (146 tests in total).

### Added (2.1 — roles)

- **auth**: Role-based access control with five roles: Administrator, Manajer Keamanan, Analis Keamanan, Pengembang, and Auditor.
  - Roles and permissions are defined in one place (`backend/core/roles.py`) and enforced per endpoint.
  - Decision updates are checked field by field.
  - New endpoints: `GET /api/v1/roles` and `PATCH /api/v1/users/{username}`.
  - The system always keeps at least one active admin, and users cannot deactivate themselves.
  - The bootstrap account is now an Administrator.
- **frontend**: User management shows an editable role dropdown per user, a role dropdown in the create form, and a role/permission table. Controls across pages follow the logged-in user's permissions.
- **test**: 17 RBAC tests (133 tests in total).

### Changed (2.1 — practical DSS)

- **dss**: The decision unit is now an **issue**: one OWASP ZAP alert type + CWE, with all affected endpoints and source files as evidence, and a stable `ISU-XXXXXX` code. Pairs are no longer the unit (35 pairs → 8 issues in the sample session).
- **dss**: P1–P4 priority tiers are now produced by rules. These rules can consider analyst-assessed business impact. MCDM only orders issues within a tier, so the list order and the recommended action can no longer contradict each other.
- **dss**: Plain-language explanations that cite only the factors that actually distinguish an issue from the others.
- **dss**: Removed the path-pattern asset criticality rules from the sample config; they demoted every finding under a `docs-assets/` folder. SLA starting values are 7/30/90 days/none, labelled as starting points.
- **dss**: The agreement metric now counts "follow recommendation" as agreement.
- **frontend**: A new landing page, *Prioritas Perbaikan*, is the work queue: issue cards with fix guidance (ZAP solution), affected locations, inline follow-up (status, owner, due date, business impact, effort, priority override), and history. *Rekomendasi Keputusan* and *Log Keputusan* are replaced by this page and by a read-only *Riwayat Keputusan*. *Bobot Kriteria* became *Pengaturan Prioritas* (rules + SLA, with weights and AHP under advanced settings). MCDM details are shown only in research mode.
- **backend**: Alembic revision `0003_issue_decisions` adds `title` and `owner` to `dss_decisions`.
- **test**: 116 tests in total, including new tests for issue grouping, priority ordering, business-impact escalation, honest explanations, priority overrides, and the agreement metric.

Overhaul into a **Decision Support System (DSS)**. Detailed, per-phase notes (in Indonesian), including deviations from the plan and open decisions: [docs/CATATAN_PERUBAHAN_DSS.md](docs/CATATAN_PERUBAHAN_DSS.md). The thesis baseline is tagged `v1.0.0-tesis`; a golden regression test guarantees identical scores.

### Added

- **dss**: Pure decision layer `backend/dss/`:
  - MCDM ranking (TOPSIS, SAW, WP) over criteria built from stored hybrid pairs: hybrid score, True Positive status, CWE exploitability and impact (CVSS 4.0 metrics from the CWE lookup table), prevalence, asset criticality, and remediation effort;
  - AHP weighting with consistency ratio check and group aggregation;
  - ordered recommendation rules with policy-based SLA (null by default);
  - per-criterion explanations;
  - weight and escalation-rate sensitivity analysis;
  - evaluation metrics (Spearman, Kendall, Precision@k, agreement rate, Kendall's W).
- **dss**: Persistence of every ranking run (method, weights, weighting source, config hash, ER, model version) in `dss_runs`, analyst decisions in `dss_decisions`, and an append-only audit trail in `dss_decision_events`. Re-ranking never overwrites analyst decisions.
- **backend**: FastAPI app factory with lifespan, domain routers under `/api/v1` (ingest, batches, history, correlation, research, SUS, auth, dss, decisions), batch endpoints replacing per-finding UI requests, and Excel export of the decision log.
- **backend**: SQLAlchemy 2.0 models and Alembic migrations. Revision `0001` adopts v1 databases idempotently without data changes; `0002` adds DSS tables and structured `scan_history` columns (`mitigation_text`, `sast_score`, `dast_score`, `is_true_positive`, `decision_key`, `model_version`, ...). SQLite runs in WAL mode.
- **backend**: Centralised settings (`pydantic-settings`, `HAST_*` variables), Argon2 password hashing, and JWT login with `analyst` / `manager` roles. The first manager account is bootstrapped from the environment.
- **frontend**: Multipage navigation, sidebar login, and the pages *Rekomendasi Keputusan*, *Log Keputusan*, *Bobot Kriteria*, *Pengguna*, and the dev page *Sensitivitas & Evaluasi DSS*.
- **ops**:
  - `pyproject.toml` + `uv.lock` (exact versions; scikit-learn 1.9.1 to keep the pickled artifacts loadable);
  - Dockerfile, docker-compose (API, UI, Caddy HTTPS), and systemd units;
  - Gitea CI (`uv lock --check` + pytest) and a manual deploy workflow;
  - SQLite online backup tool with retention;
  - `.env.sample`.
- **tools**: Golden baseline generator (`tools/regression`), offline DSS evaluation CLI (`tools/dss_evaluation`), and DSS ranking latency benchmark.
- **test**:
  - golden regression (94 SAST, 20 DAST, 35 hybrid pairs identical to v1);
  - DSS unit tests with independently computed reference values;
  - DSS/decision/auth API tests;
  - v1 database adoption test;
  - backup tool test.

  Total 109 tests. Tests that need the gitignored model artifacts are skipped automatically when the artifacts are absent.

### Changed

- **frontend**: The UI is now a thin API client. `frontend/utils/database.py` was removed, so no SQLite access remains in `frontend/`. Report parsing, CWE resolution, batch scoring, hybrid correlation, and SHAP persistence moved to the backend. All API calls now use timeouts.
- **frontend**: Deleting history and listing SUS responses (personal data) now require login.
- **backend**: `sonar_cwe_mapper` moved to `backend/services/parsers/` (logic unchanged).
- **ai-model**: The training pipeline writes research metrics through the backend repository.
- **tests**: The API test client uses an isolated temporary database instead of `database/database.db`. v1 test names and assertions are preserved.
- **ops**: `app.sh.sample` uses `uv` and no longer enables `--reload` unless `HAST_DEV=1`. `requirements.txt` is now exported from `uv.lock`.

### Fixed

- The dev black-box page no longer writes and deletes test rows in the research database; DB scenarios run against a temporary database.
- Hybrid results now persist the individual SAST/DAST scores and the True Positive flag (previously lost after display).

## [1.0.0] - 2026-11-13

### Added

- **ai-model**: Initial release of the core AI vulnerability quantification engine powered by **Random Forest Regressor** trained on empirical NVD CVSS v4.0 vulnerability records.
- **ai-model**: Automated 4-stage data lifecycle and training pipeline orchestrator (`pipeline_engine.py`) integrating raw NVD JSON extraction (`dataset_collector.py`), CWE lookup table profiling (`cwe_profiler.py`), 100% population model training (`train_production_model.py`), and system summary manifest synchronization (`update_system_summary()`).
- **ai-model**: Automated TF-IDF text feature extraction pipeline with configurable vocabulary size (`max_features: 5000`) and 5-fold cross-validation / 80:20 train-test split evaluation metrics (MAE, RMSE, $R^2$, Accuracy, Precision, Recall, F1-Score).
- **ai-model**: Centralized SQLite database schema initialization and persistence layer for research dataset metadata, CVSS v4.0 severity distribution, and model validation evaluation metrics.
- **backend**: High-performance RESTful API service powered by **FastAPI** (`backend/api.py`) exposing endpoints for single vulnerability prediction (`POST /predict`), hybrid correlation prediction (`POST /predict/hybrid`), SHAP token attribution (`POST /predict/shap`), sample security reports (`GET /sample-reports/{filename}`), and live server summary metadata (`GET /system_summary.json`).
- **backend**: Explainable AI (XAI) engine (`backend/engine.py`) powered by SHAP (`TreeExplainer`) calculating additive feature attributions (`Base Score`, `SHAP Base Value`, `Total SHAP Positive`, `Total SHAP Negative`, and `SHAP Predicted Score`) with absent vocabulary bias mitigation.
- **backend**: Intelligent scope pre-filtering Gatekeeper v2 (`backend/config/excluded_domains.json`) to automatically filter out third-party/out-of-scope domain noise.
- **frontend**: Decoupled, modular **Streamlit** dashboard architecture (`frontend/app.py`) organized across 6 dedicated tabs:
  - **Tab 1 (SAST)**: SonarQube JSON analysis, batch vulnerability scoring, and CWE enrichment.
  - **Tab 2 (DAST)**: OWASP ZAP JSON ingestion and network/application layer vulnerability parsing.
  - **Tab 3 (Hybrid)**: Automated CWE ID-based correlation matching, True Positive identification using Left-Base strategy, and dynamic priority escalation scoring.
  - **Tab 4 (SHAP Visual)**: Dedicated XAI transparency charts, feature importance rankings, and synchronized Beeswarm distribution plots (`px.strip`).
  - **Tab 5 (Analisis)**: Empirical research evaluation answering RQ1 (ML model performance & CVSS v4.0 alignment) and RQ2 (SHAP explainability & NLP feature importance).
  - **Tab 6 (Simulasi)**: Real-time interactive model simulation, custom CVE scenario testing, and live SHAP contribution breakdown.
- **frontend**: Historical session management with SQLite persistence, search and severity filtering, interactive deletion modals, and standardized RFC 4180 CSV report export with embedded SHAP quantification metrics.
- **frontend**: Multi-tier dynamic SonarQube rules to MITRE CWE mapping engine (`frontend/utils/sonar_cwe_mapper.py`) with hierarchical rule key lookup, tag parsing, regex heuristics, and priority weighting.
- **tools**: Automated SonarQube rules to CWE converter utility (`tools/convert_sonar_to_cwe/app.py`) for rule parsing and cache generation.
- **ci/cd**: Automated remote deployment workflow using Gitea Actions (`.gitea/workflows/deploy.yaml`) featuring Appleboy SSH execution and systemd service management.
- **test**: Comprehensive automated Pytest test suite covering 51 unit, integration, and black-box verification scenarios (`tests/`).
