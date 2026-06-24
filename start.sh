#!/bin/bash
# start.sh — Start FastAPI service on port 8080

echo "Starting FastAPI developer API on port 8080..."
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8080
