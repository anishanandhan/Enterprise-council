import os
import csv
import json
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress insecure request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
from services.env_loader import load_env
load_env()

host = os.environ.get("SPLUNK_HOST", "localhost")
port = os.environ.get("SPLUNK_PORT", "8089")
username = os.environ.get("SPLUNK_USERNAME", "admin")
password = os.environ.get("SPLUNK_PASSWORD", "")
token = os.environ.get("SPLUNK_TOKEN", "")

if not password and not token:
    print("Error: Neither SPLUNK_PASSWORD nor SPLUNK_TOKEN configured in .env")
    exit(1)

base_url = f"https://{host}:{port}"

# Setup request options
request_kwargs = {"verify": False}
if token:
    request_kwargs["headers"] = {"Authorization": f"Bearer {token}"}
else:
    request_kwargs["auth"] = HTTPBasicAuth(username, password)

# Indexes to create and populate
datasets = {
    "security": "security_logs.csv",
    "infrastructure": "infra_logs.csv",
    "business": "business_logs.csv",
    "compliance": "compliance_logs.csv"
}

def create_index(index_name):
    """Create a Splunk index if it doesn't already exist."""
    print(f"Checking index '{index_name}'...")
    
    # Check if index already exists
    check_url = f"{base_url}/services/data/indexes/{index_name}"
    response = requests.get(check_url, **request_kwargs)
    if response.status_code == 200:
        print(f"  Index '{index_name}' already exists.")
        return True
        
    print(f"  Index '{index_name}' not found. Creating index...")
    url = f"{base_url}/services/data/indexes"
    data = {"name": index_name}
    
    response = requests.post(url, data=data, **request_kwargs)
    if response.status_code in (200, 201):
        print(f"  Created index '{index_name}' successfully.")
        return True
    else:
        print(f"  Failed to create index '{index_name}': {response.status_code} - {response.text}")
        return False

def ingest_csv(index_name, csv_filename):
    """Ingest CSV rows as JSON events into a Splunk index."""
    # Find dataset directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "datasets", csv_filename)
    
    if not os.path.exists(csv_path):
        print(f"CSV file not found: {csv_path}")
        return
        
    print(f"Ingesting {csv_filename} into index '{index_name}'...")
    
    # Simple receiver endpoint
    url = f"{base_url}/services/receivers/simple"
    params = {
        "index": index_name,
        "sourcetype": "_json"
    }
    
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            # Post each row as a JSON payload
            payload = json.dumps(row)
            response = requests.post(url, params=params, data=payload, **request_kwargs)
            if response.status_code in (200, 201, 204):
                count += 1
            else:
                print(f"  Failed to ingest row: {row}. Status: {response.status_code}")
                
        print(f"  Ingested {count} events into '{index_name}'.")

def main():
    print("\nEnterprise Council AI — Splunk Data Ingestion Utility")
    print("=" * 60)
    
    # 1. Create indexes
    for index in datasets.keys():
        create_index(index)
        
    print("-" * 60)
    
    # 2. Ingest CSV data
    for index, filename in datasets.items():
        ingest_csv(index, filename)
        
    print("=" * 60)
    print("Ingestion Complete!")
    print("   You can now search in Splunk using:")
    print("   index=infrastructure   OR   index=security")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
