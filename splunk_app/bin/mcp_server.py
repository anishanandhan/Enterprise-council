#!/usr/bin/env python
import sys
import os

# Ensure the parent app directories are on the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from splunk.mcp_client import run_stdio_server

if __name__ == "__main__":
    run_stdio_server()
