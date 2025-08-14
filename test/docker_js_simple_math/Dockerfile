# syntax=docker/dockerfile:1.7

# Use official Node.js image
FROM node:22-alpine AS base

# Install build tools for dependencies if needed (libsodium for ed25519 may be required by solana-py)
RUN apk add --no-cache \
	build-base \
	pkgconf \
	libsodium \
	git

# Install javascript test
WORKDIR /app/
COPY javascript/package.json ./
RUN npm install --omit=dev
COPY javascript/src ./src


# --- Scanner stage: does NOT contaminate what is scanned ---
FROM python:3.12-alpine AS scanner
RUN apk add --no-cache git
RUN python -m venv /opt/venv

# Install the local version of ossprey-python-client
COPY --from=local-package / /workspaces/ossprey-python-client
RUN  /bin/sh -lc '. /opt/venv/bin/activate && \
      pip install --no-cache-dir /workspaces/ossprey-python-client'

# Mount the entire root fs of `base` at /scanfs (read-only) and scan that.
RUN --mount=type=bind,from=base,source=/,target=/scanfs,ro \
    /bin/sh -lc '. /opt/venv/bin/activate && \
      mkdir -p /scan-result && \
      python -u -m ossprey --mode fs --dir /scanfs -o /scan-result/sbom.json --dry-run --verbose '

FROM scratch AS sbom-export
# Export SBOM; retrieve to local disk with:
#   docker buildx build --target sbom-export --output type=local,dest=. .
COPY --from=scanner /scan-result/sbom.json /sbom.json
# TODO fix location return from scanning
# TODO LABEL org.opencontainers.image.sbom=/tmp/sbom.spdx.json

# --- Final image ---
FROM base AS final

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
