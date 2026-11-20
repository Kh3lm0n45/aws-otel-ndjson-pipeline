#!/usr/bin/env bash
# Pre-publish leak scan. Run from the repo root before every push.
#
#   scripts/leak_scan.sh [path-to-private-patterns-file]
#
# Generic checks are built in. Organisation, vendor and personal terms live in a PRIVATE
# patterns file that must never be committed (one case-insensitive regex per
# line). See leak-patterns.example.txt for the format.
set -u
fail=0
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here" || exit 2
files() { git ls-files 2>/dev/null || find . -type f -not -path './.git/*' -not -name '*.pyc' -not -path '*/__pycache__/*' -not -path './.pytest_cache/*'; }

check() { # label, grep -E pattern, [grep -v pattern to allow]
  local hits
  hits=$(files | xargs grep -InE -- "$2" 2>/dev/null | { if [ -n "${3:-}" ]; then grep -vE -- "$3"; else cat; fi; })
  if [ -n "$hits" ]; then echo "FAIL [$1]"; echo "$hits"; fail=1; fi
}

check "12-digit AWS account id (only 123456789012 allowed)" '(^|[^0-9])[0-9]{12}([^0-9]|$)' '123456789012|[0-9]{13,}|\.json|logs_[0-9]+|timeUnixNano|[0-9]{19}'
check "AWS access key id"          'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
check "secret-looking assignment"  '(secret|password|token)[^a-z]{0,5}[=:][^,]{8,}' 'example|placeholder'
check "private key material"       'BEGIN (RSA |EC )?PRIVATE KEY'
check "non-example IPv4 (only 10.0.0.x allowed)" '([0-9]{1,3}\.){3}[0-9]{1,3}' '10\.0\.0\.[0-9]+|0\.0\.0\.0'
check "non-example email"          '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' '@example\.(com|org)'
check "non-placeholder ARN account" 'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:' 'arn:aws:[a-z0-9-]+:[a-z0-9-]*:123456789012:'

pf="${1:-.leak-patterns.private}"
if [ -f "$pf" ]; then
  while IFS= read -r pat; do
    [ -z "$pat" ] && continue; case "$pat" in \#*) continue;; esac
    hits=$(files | xargs grep -InEi -- "$pat" 2>/dev/null)
    if [ -n "$hits" ]; then echo "FAIL [private pattern: $pat]"; echo "$hits"; fail=1; fi
  done < "$pf"
else
  echo "WARN: no private patterns file ($pf). Private terms NOT checked."; fail=1
fi

[ $fail -eq 0 ] && echo "leak scan clean" || { echo "leak scan FAILED"; exit 1; }
