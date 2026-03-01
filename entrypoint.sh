#!/bin/sh
set -e

# ClosedSSPM GitHub Action entrypoint.
# Maps action inputs (INPUT_*) to CLI flags and writes outputs to $GITHUB_OUTPUT.

# --- Map inputs to env vars expected by the CLI ---
export SNOW_INSTANCE="${INPUT_INSTANCE:-}"
export SNOW_USERNAME="${INPUT_USERNAME:-}"
export SNOW_PASSWORD="${INPUT_PASSWORD:-}"
export SNOW_CLIENT_ID="${INPUT_CLIENT_ID:-}"
export SNOW_CLIENT_SECRET="${INPUT_CLIENT_SECRET:-}"
export SNOW_KEY_ID="${INPUT_KEY_ID:-}"
export SNOW_JWT_USER="${INPUT_JWT_USER:-}"

# --- Handle private key (PEM content → temp file) ---
if [ -n "${INPUT_PRIVATE_KEY:-}" ]; then
  PRIVATE_KEY_FILE="/tmp/.closedsspm-key.pem"
  printf '%s\n' "${INPUT_PRIVATE_KEY}" > "${PRIVATE_KEY_FILE}"
  chmod 600 "${PRIVATE_KEY_FILE}"
  export SNOW_PRIVATE_KEY_PATH="${PRIVATE_KEY_FILE}"
fi

PLATFORM="${INPUT_PLATFORM:-servicenow}"
FORMAT="${INPUT_FORMAT:-sarif}"
FAIL_ON="${INPUT_FAIL_ON:-none}"

# --- Determine output file extension ---
case "${FORMAT}" in
  html)  EXT="html" ;;
  json)  EXT="json" ;;
  csv)   EXT="csv"  ;;
  sarif) EXT="sarif" ;;
  *)     EXT="json" ;;
esac

REPORT_FILE="/tmp/closedsspm-report.${EXT}"
SNAPSHOT_FILE="/tmp/closedsspm-snapshot.json"

# --- Build CLI arguments ---
ARGS="audit"
ARGS="${ARGS} --platform ${PLATFORM}"
ARGS="${ARGS} --format ${FORMAT}"
ARGS="${ARGS} --output ${REPORT_FILE}"
ARGS="${ARGS} --save-snapshot ${SNAPSHOT_FILE}"

if [ "${FAIL_ON}" != "none" ] && [ -n "${FAIL_ON}" ]; then
  ARGS="${ARGS} --fail-on ${FAIL_ON}"
fi

# --- Run audit ---
# Exit code 0 = success, 1 = tool error, 2 = findings above threshold.
# We capture exit code to write outputs before propagating.
EXIT_CODE=0
closedsspm ${ARGS} || EXIT_CODE=$?

# On tool error (exit 1), bail immediately.
if [ "${EXIT_CODE}" -eq 1 ]; then
  echo "::error::ClosedSSPM audit failed (tool error)"
  exit 1
fi

# --- Extract summary from snapshot for outputs ---
FINDING_COUNT="unknown"
POSTURE_SCORE="unknown"

# Run a quick evaluate to get JSON summary (reuse snapshot).
if [ -f "${SNAPSHOT_FILE}" ]; then
  SUMMARY_FILE="/tmp/closedsspm-summary.json"
  closedsspm evaluate --snapshot "${SNAPSHOT_FILE}" --format json --output "${SUMMARY_FILE}" 2>/dev/null || true
  if [ -f "${SUMMARY_FILE}" ]; then
    FINDING_COUNT=$(grep -o '"total":[0-9]*' "${SUMMARY_FILE}" | head -1 | cut -d: -f2)
    POSTURE_SCORE=$(grep -o '"posture_score":"[^"]*"' "${SUMMARY_FILE}" | head -1 | cut -d'"' -f4)
  fi
fi

# --- Write outputs ---
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "report-path=${REPORT_FILE}" >> "${GITHUB_OUTPUT}"
  echo "finding-count=${FINDING_COUNT:-0}" >> "${GITHUB_OUTPUT}"
  echo "posture-score=${POSTURE_SCORE:-unknown}" >> "${GITHUB_OUTPUT}"
  if [ "${FORMAT}" = "sarif" ]; then
    echo "sarif-path=${REPORT_FILE}" >> "${GITHUB_OUTPUT}"
  fi
fi

# --- Write step summary ---
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## ClosedSSPM Audit Results"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Platform | ${PLATFORM} |"
    echo "| Instance | (masked) |"
    echo "| Findings | ${FINDING_COUNT:-0} |"
    echo "| Posture Score | ${POSTURE_SCORE:-unknown} |"
    echo "| Format | ${FORMAT} |"
    echo "| Fail Threshold | ${FAIL_ON} |"
    echo ""
    if [ "${EXIT_CODE}" -eq 2 ]; then
      echo "> **⚠️ Findings at or above ${FAIL_ON} severity detected.**"
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi
# --- Cleanup sensitive temp files ---
rm -f /tmp/.closedsspm-key.pem

# Propagate exit code 2 (findings above threshold) to fail the step.
exit "${EXIT_CODE}"
