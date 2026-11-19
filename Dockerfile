# Satu image untuk kedua layanan (API dan UI). Halaman Simulasi / Black-Box (khusus mode dev) menjalankan kode model
# di dalam proses, sehingga kontainer UI memerlukan kode yang sama dan akses baca saja ke artefak model.
FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.8 /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependensi lebih dulu (layer ter-cache), persis sesuai kuncian uv.lock.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Kode aplikasi. Data runtime (database/, ai-model/artifacts, ai-model/data, konfigurasi *.json) di-mount dari host.
COPY backend ./backend
COPY frontend ./frontend
COPY ai-model ./ai-model
COPY tools ./tools
COPY sample-reports ./sample-reports
COPY .streamlit ./.streamlit
COPY alembic.ini requirements.txt ./

RUN useradd --create-home --uid 10001 hast && mkdir -p /app/database /app/logs && chown -R hast /app/database /app/logs
USER hast

EXPOSE 8000 8501
CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]
