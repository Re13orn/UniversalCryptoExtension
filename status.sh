#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
    ""|full) ;;
    minimal|simple|adapter) echo "Retired entry point: only UniversalCryptoExtension is shipped. SPI was not modified." >&2; exit 1 ;;
    *) echo "Usage: ./status.sh [full]" >&2; exit 1 ;;
esac
ARTIFACT="$(python3 "$PROJECT_DIR/scripts/verify_distribution.py" --pom-property artifactId)"
VERSION="$(python3 "$PROJECT_DIR/scripts/verify_distribution.py" --pom-property version)"
REVISION="$(python3 "$PROJECT_DIR/scripts/verify_distribution.py" --pom-property uce.revision)"
python3 "$PROJECT_DIR/scripts/verify_distribution.py" --expected-revision "$REVISION" --jar "$PROJECT_DIR/target/$ARTIFACT-$VERSION.jar"
echo "This checks the local artifact, not whether Burp has loaded it."
