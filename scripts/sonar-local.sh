#!/usr/bin/env bash
# Local SonarCloud analysis: run tests + lint to produce the reports Sonar
# consumes, then invoke sonar-scanner against SonarCloud. Requires SONAR_TOKEN.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${SONAR_TOKEN:?SONAR_TOKEN must be set}"
# Keep the token out of the ambient environment for the test and lint steps,
# which execute code from the checkout. This narrows accidental exposure; it is
# not a boundary against hostile code running as the same user, so do not run
# this against a checkout you do not trust.
_sonar_token="$SONAR_TOKEN"
unset SONAR_TOKEN

go test -race -coverprofile=coverage.out ./...
golangci-lint run --timeout=5m

BRANCH=$(git rev-parse --abbrev-ref HEAD)
# SONAR_TOKEN is read from the environment by sonar-scanner; never pass it as a
# CLI property (visible in process listings). It is scoped to this single
# command only, never exported globally.
SONAR_TOKEN="$_sonar_token" sonar-scanner \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.branch.name="${BRANCH}" \
  -Dsonar.qualitygate.wait=true
