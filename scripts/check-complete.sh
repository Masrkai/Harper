#!/usr/bin/env bash
set -euo pipefail

PLAN_FILE="task_plan.md"
if [ ! -f "$PLAN_FILE" ]; then
    echo "Error: $PLAN_FILE not found."
    exit 1
fi

# Check that every phase has Status: complete (or similar, or no pending/in_progress)
if grep -i "Status:.*pending" "$PLAN_FILE" || grep -i "Status:.*in_progress" "$PLAN_FILE"; then
    echo "NOT COMPLETE: Some phases are still pending or in progress."
    exit 1
else
    echo "ALL PHASES COMPLETE"
    exit 0
fi
