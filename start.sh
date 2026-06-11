#!/bin/bash
# start.sh — Start both FastAPI and Streamlit services

# 1. Start the FastAPI API server in the background
echo "Starting FastAPI developer API on port 8001..."
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8001 &

# 2. Start the Streamlit frontend in the foreground on port 8080
echo "Starting Streamlit Operational Command Center on port 8080..."
streamlit run frontend/app.py --server.port 8080 --server.address 0.0.0.0
