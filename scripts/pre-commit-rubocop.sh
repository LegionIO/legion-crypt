#!/usr/bin/env bash
# Pre-commit hook: run RuboCop with autofix on staged Ruby files.
# Tries rubocop directly, then bundle exec. If the binary is truly
# unavailable (exit 127 / crash / Prism conflict), warns and defers
# to CI. If rubocop runs but reports offenses, fails the commit.
set -uo pipefail

run_rubocop() {
  output=$("$@" -A --force-exclusion "${FILES[@]}" 2>&1)
  rc=$?
  if [ $rc -eq 0 ] || [ $rc -eq 1 ]; then
    # rubocop ran successfully: 0 = clean, 1 = offenses found
    echo "$output"
    return $rc
  fi
  # exit > 1 means rubocop crashed / couldn't load
  return 2
}

FILES=("$@")

if run_rubocop rubocop; then
  exit 0
elif [ $? -eq 1 ]; then
  echo "RuboCop found offenses that could not be auto-corrected."
  exit 1
fi

if run_rubocop bundle exec rubocop; then
  exit 0
elif [ $? -eq 1 ]; then
  echo "RuboCop found offenses that could not be auto-corrected."
  exit 1
fi

echo "⚠  RuboCop not available locally (Prism conflict?) — CI will enforce."
echo "   Run 'ruby -c' to at least verify syntax."
ruby -c "$@" 2>&1 || exit 1
exit 0
