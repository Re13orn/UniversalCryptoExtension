#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required for distribution verification" >&2
    exit 1
fi
if ! command -v mvn >/dev/null 2>&1; then
    echo "Maven is required to build the extension" >&2
    exit 1
fi

ARTIFACT="$(python3 scripts/verify_distribution.py --pom-property artifactId)"
VERSION="$(python3 scripts/verify_distribution.py --pom-property version)"
REVISION="$(python3 scripts/verify_distribution.py --pom-property uce.revision)"
JAR="target/$ARTIFACT-$VERSION.jar"

mvn -B -ntp clean verify
python3 scripts/verify_distribution.py --jar "$JAR" --expected-revision "$REVISION" \
    --crypto-classpath target/test-classes > target/distribution-verification.json
cat target/distribution-verification.json
printf 'JAR: %s\n' "$JAR"
