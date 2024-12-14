# SNIFFER
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim-bookworm AS base

RUN apt-get update && apt-get install -y nano net-tools tcpdump iputils-ping dnsutils


# BUILD STAGE
FROM base AS build

WORKDIR /app
ARG POETRY_VERSION
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

RUN pip install poetry==${POETRY_VERSION}
COPY pyproject.toml poetry.lock ./
COPY lib ./lib
RUN touch README.md
RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --only main,sniffer


# FINAL STAGE
FROM base AS final

WORKDIR /app
ENV VIRTUAL_ENV="/app/.venv"
ENV PATH="${VIRTUAL_ENV}/bin:$PATH"

COPY --from=build $VIRTUAL_ENV $VIRTUAL_ENV
COPY service/sniffer/ .
CMD ["python", "sniffer.py"]