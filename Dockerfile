# @license GPL-3.0-or-later
# Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# For more information, visit <https://www.gnu.org/licenses/>.
# ---------------------------------------------------------------------------------------
# Dockerfile – Omnixys Authentication Service
# Multi-stage build optimized for security, reproducibility, and minimal runtime size.
# ---------------------------------------------------------------------------------------
# syntax=docker/dockerfile:1.14.0

ARG NODE_VERSION=24.10.0

# ---------------------------------------------------------------------------------------
# Stage 0: Base image
# - Common setup for all later build stages.
# - Corepack is enabled to support pnpm package manager.
# ---------------------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS base
WORKDIR /home/node
RUN corepack enable pnpm

# ---------------------------------------------------------------------------------------
# Stage 1: Build (dist)
# - Installs all dependencies (including dev) and compiles the TypeScript project.
# - Result: ./dist folder containing compiled JS files.
# ---------------------------------------------------------------------------------------
FROM base AS dist
COPY --chown=node:node package.json pnpm-lock.yaml ./

RUN --mount=type=secret,id=omnixys_token \
    TOKEN=$(cat /run/secrets/omnixys_token) && \
    echo "@omnixys:registry=https://npm.pkg.github.com" > .npmrc && \
    echo "//npm.pkg.github.com/:_authToken=${TOKEN}" >> .npmrc && \
    pnpm install --frozen-lockfile --ignore-scripts

COPY --chown=node:node . .
RUN pnpm run build

# ---------------------------------------------------------------------------------------
# Stage 2: Production dependencies
# - Installs only production dependencies to keep image small.
# - No dev packages or build tools are included.
# ---------------------------------------------------------------------------------------
FROM base AS dependencies

COPY --chown=node:node package.json pnpm-lock.yaml ./

RUN --mount=type=secret,id=omnixys_token \
    TOKEN=$(cat /run/secrets/omnixys_token) && \
    echo "@omnixys:registry=https://npm.pkg.github.com" > .npmrc && \
    echo "//npm.pkg.github.com/:_authToken=${TOKEN}" >> .npmrc && \
    pnpm install --frozen-lockfile --ignore-scripts

# ---------------------------------------------------------------------------------------
# Stage 3: Final runtime image
# - Copies only compiled code and production node_modules.
# - Runs the app as a non-root user for security.
# ---------------------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS final

# ----- Build-time arguments -----
ARG NODE_VERSION
ARG APP_NAME
ARG APP_VERSION
ARG CREATED
ARG REVISION

# ----- Image metadata (OCI compliant) -----
LABEL org.opencontainers.image.title="${APP_NAME}-service" \
      org.opencontainers.image.description="Omnixys ${APP_NAME}-service – Node.js ${NODE_VERSION}, built with TypeScript, version ${APP_VERSION}, based on Debian Bookworm." \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.vendor="Omnixys Technologies" \
      org.opencontainers.image.authors="caleb.gyamfi@omnixys.com" \
      org.opencontainers.image.base.name="node:${NODE_VERSION}-bookworm-slim" \
      org.opencontainers.image.url="https://github.com/omnixys/${APP_NAME}-service" \
      org.opencontainers.image.source="https://github.com/omnixys/${APP_NAME}-service" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.documentation="https://github.com/omnixys/${APP_NAME}-service/blob/main/README.md"

# ----- Set working directory -----
WORKDIR /opt/app

# ----- Environment configuration -----
# NODE_ENV=production ensures that dev dependencies are ignored and improves runtime performance.
# TZ=UTC ensures consistent timestamps across environments.
ENV NODE_ENV=production TZ=UTC

# ----- Install required system packages -----
# dumb-init: lightweight init system for proper signal handling.
# wget + ca-certificates: used for health checks and secure HTTPS.
RUN apt-get update && \
    apt-get install -y --no-install-recommends dumb-init wget ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* && \
    mkdir -p /opt/app/log && chown -R node:node /opt/app

# ----- Enable pnpm (runtime) -----
RUN corepack enable pnpm

# ----- Switch to non-root user -----
USER node

# ----- Copy built artifacts and dependencies -----
COPY --from=dependencies --chown=node:node /home/node/node_modules ./node_modules
COPY --from=dist --chown=node:node /home/node/dist ./dist
COPY --chown=node:node package.json ./

# ----- Expose application port (per Omnixys port conventions) -----
EXPOSE 3000

# ----- Healthcheck -----
# Ensures that Docker and orchestration systems (e.g., Kubernetes) can detect unhealthy containers.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:3000/health || exit 1

# ----- Start command -----
# dumb-init ensures proper signal forwarding and zombie process cleanup.
ENTRYPOINT ["dumb-init", "node", "dist/main.js"]
