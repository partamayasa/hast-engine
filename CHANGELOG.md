<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

# Changelog

All notable changes to the **Decision Support System for Prioritising the Remediation of Web Application Vulnerabilities Based on Explainable Artificial Intelligence and CVSS v4.0** project are documented in this file.

## [1.0.0] - 2026-11-27

Initial release of **HAST DSS (Prioritas Remediasi Kerentanan)** — integrating SAST (SonarQube) and DAST (OWASP ZAP) vulnerability scanning, Random Forest CVSS v4.0 severity prediction, Explainable AI (SHAP), and Multi-Criteria Decision Making (MCDM/AHP).

### Added

- **AI & Scoring Engine (`backend/engine.py`, `ai-model/`)**:
  - TF-IDF + Random Forest Regressor severity prediction (`CVSS v4.0`) with absent-vocabulary bias mitigation.
  - Per-finding additive SHAP explanation (`TreeExplainer`) computed and persisted during batch scoring and hybrid correlation.
  - Hybrid SAST–DAST correlation using CWE matching and configurable escalation rate, while preserving single-scanner findings (*Temuan Pemindai Tunggal*).
- **Decision Support System (`backend/dss/`)**:
  - Issue aggregation by `(cwe_id, alert/component)` across hybrid pairs and single-scanner findings.
  - Consecutive criteria C1–C7, priority classification (`P1`–`P4`) with SLA deadlines, and MCDM ranking (`TOPSIS`, `SAW`, `WP`) with AHP weight consistency checking.
  - Sensitivity analysis, evaluation metrics (`Spearman`, `Kendall`, `Precision@k`, `Kendall's W`), and analyst decision tracking with append-only audit trail.
- **Backend API & Auth (`backend/routers/v1/`, `backend/db/`)**:
  - FastAPI REST API (`/api/v1/*`) as the single owner of the SQLite/SQLAlchemy database with Alembic migrations (`0001`–`0006`).
  - JWT authentication with Argon2 password hashing and 5-role RBAC (`admin`, `manager`, `analyst`, `developer`, `auditor`).
  - Required runtime configuration (`backend/config/dss_config.json`) validated at startup.
- **Frontend Dashboard (`frontend/`)**:
  - Multipage Streamlit thin client (`Dasbor`, `Prioritas Perbaikan`, `Riwayat Keputusan`, `SonarQube (SAST)`, `OWASP ZAP (DAST)`, `Korelasi Hybrid`, `Pengguna`, and `?dev=true` research/QA tools).
- **Tools & Test Suite (`tools/`, `tests/`)**:
  - Operational and research utilities (`backup_db`, `benchmark_latency`, `convert_sonar_to_cwe`, `cwe_profile_sensitivity`, `dss_evaluation`, `dss_followup_import`, `hybrid_verification`, `visualization`).
  - Automated `pytest` suite covering AI scoring, API endpoints, RBAC, DSS logic, database migrations, and golden regression baseline.
