"""
splunk_client.py — Splunk REST API Client

Connects to Splunk Enterprise via the REST API.
Runs SPL queries and returns results as lists of dicts.

    Python
       ↓
    Splunk REST API
       ↓
    Results

Environment variables required:
    SPLUNK_HOST     — Splunk server hostname (default: localhost)
    SPLUNK_PORT     — Management port (default: 8089)
    SPLUNK_USERNAME — Splunk username
    SPLUNK_PASSWORD — Splunk password
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import io
import time
import urllib.request
import urllib.parse
import json
import ssl

def rewrite_query_for_spath(spl_query):
    query = spl_query.strip()
    if "spath" in query.lower():
        return query
    
    # Check if query targets our json indices
    targets_json_index = False
    for idx in ["security", "infrastructure", "business", "compliance"]:
        if f"index={idx}" in query or f"index=\"{idx}\"" in query or f"index='\''{idx}'\''" in query:
            targets_json_index = True
            break
            
    if not targets_json_index:
        return query
        
    # Split by the first pipe
    parts = query.split("|", 1)
    first_part = parts[0].strip()
    
    # Extract the index filter from the first part
    index_term = None
    other_terms = []
    
    # Split first part by space/token
    tokens = first_part.split()
    for token in tokens:
        if token.startswith("index="):
            index_term = token
        elif token.lower() == "search":
            pass
        else:
            other_terms.append(token)
            
    if not index_term:
        return query
        
    rewritten_first = index_term
    if other_terms:
        other_str = " ".join(other_terms)
        rewritten_first += f" | spath | search {other_str}"
    else:
        rewritten_first += " | spath"
        
    if len(parts) > 1:
        return f"{rewritten_first} | {parts[1].strip()}"
    return rewritten_first


class SplunkClient:

    def __init__(self):
        self.host = os.environ.get("SPLUNK_HOST", "localhost")
        self.port = os.environ.get("SPLUNK_PORT", "8089")
        self.username = os.environ.get("SPLUNK_USERNAME", "admin")
        self.password = os.environ.get("SPLUNK_PASSWORD", "")
        self.token = os.environ.get("SPLUNK_TOKEN", None)
        self.base_url = f"https://{self.host}:{self.port}"

        # Production SSL Validation Check
        self.ssl_context = ssl.create_default_context()
        ca_file = os.environ.get("SPLUNK_SSL_CA")
        ignore_ssl = os.environ.get("SPLUNK_IGNORE_SSL", "true").lower() == "true"
        
        if ca_file and os.path.exists(ca_file):
            self.ssl_context.load_verify_locations(cafile=ca_file)
            self.ssl_context.check_hostname = True
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
            print(f"  [Security] Verifying Splunk SSL certificates using CA file: {ca_file}")
        elif not ignore_ssl:
            self.ssl_context.check_hostname = True
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
            print("  [Security] Verifying Splunk SSL certificates using system default CA bundle.")
        else:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            print("  [Security Warning] SSL validation disabled for Splunk connection (check SPLUNK_IGNORE_SSL). Vulnerable to MitM.")

    def _request(self, method, path, data=None, params=None):
        """Make an authenticated request to the Splunk REST API."""
        url = f"{self.base_url}{path}"

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if data:
            data = urllib.parse.urlencode(data).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)

        # Auth via token if we have one, otherwise basic auth
        if self.token:
            auth_prefix = "Bearer" if os.environ.get("SPLUNK_TOKEN") == self.token else "Splunk"
            req.add_header("Authorization", f"{auth_prefix} {self.token}")
        else:
            print("  [Security Warning] Using basic credentials auth fallback instead of token-based authentication.")
            if os.environ.get("BLOCK_BASIC_AUTH", "false").lower() == "true":
                raise PermissionError("Security Policy Violation: Basic Authentication is blocked. Configure a SPLUNK_TOKEN.")
            import base64
            credentials = base64.b64encode(
                f"{self.username}:{self.password}".encode()
            ).decode()
            req.add_header("Authorization", f"Basic {credentials}")

        response = urllib.request.urlopen(req, context=self.ssl_context)
        return response.read().decode("utf-8")

    def login(self):
        """Authenticate and get a session token or verify token."""
        if self.token:
            return True
        data = {
            "username": self.username,
            "password": self.password
        }
        result = self._request("POST", "/services/auth/login", data=data)

        # Parse XML response for session key
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result)
        self.token = root.findtext("sessionKey")
        return self.token is not None

    def search(self, spl_query, max_results=100):
        """
        Run an SPL search and return results as a list of dicts.

        This uses Splunk's oneshot search endpoint for simplicity.
        For production, you'd use async jobs.
        """
        rewritten = rewrite_query_for_spath(spl_query)
        query = rewritten.strip()
        if not (query.startswith("|") or query.startswith("search")):
            query = f"search {query}"

        data = {
            "search": query,
            "output_mode": "csv",
            "count": str(max_results),
            "earliest_time": "0",  # Search all time for hackathon demo robustness
            "latest_time": "now"
        }

        result = self._request(
            "POST",
            "/services/search/jobs/export",
            data=data
        )

        # Parse CSV response into list of dicts
        reader = csv.DictReader(io.StringIO(result))
        rows = []
        for row in reader:
            raw = row.get("_raw", "")
            if raw and (raw.strip().startswith("{") or raw.strip().startswith("[")):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        for k, v in parsed.items():
                            if k not in row or not row[k]:
                                row[k] = str(v)
                except Exception:
                    pass
            rows.append(row)
        return rows

    def test_connection(self):
        """Test if we can reach Splunk."""
        try:
            self.login()
            return True
        except Exception as e:
            print(f"Splunk connection failed: {e}")
            return False


# ── Fallback: CSV-based client for development ──────────────────

class SplunkSDKClient:
    """
    Splunk Client using the official splunk-sdk (splunklib).
    """

    def __init__(self):
        self.host = os.environ.get("SPLUNK_HOST", "localhost")
        self.port = os.environ.get("SPLUNK_PORT", "8089")
        self.username = os.environ.get("SPLUNK_USERNAME", "admin")
        self.password = os.environ.get("SPLUNK_PASSWORD", "")
        self.token = os.environ.get("SPLUNK_TOKEN", None)
        self.service = None

    def login(self):
        """Authenticate using splunklib."""
        try:
            import splunklib.client as client
            import ssl
            # Disable certificate validation for self-signed certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            kwargs = {
                "host": self.host,
                "port": int(self.port),
                "context": ssl_context
            }
            if self.token:
                kwargs["token"] = self.token
            else:
                kwargs["username"] = self.username
                kwargs["password"] = self.password

            self.service = client.connect(**kwargs)
            return True
        except Exception as e:
            # Silent fallback, prints in caller
            return False

    def search(self, spl_query, max_results=100):
        """Run SPL query using splunklib."""
        if not self.service:
            if not self.login():
                raise RuntimeError("Not connected to Splunk via SDK")

        try:
            import splunklib.results as results
            kwargs = {
                "output_mode": "json",
                "count": max_results,
                "earliest_time": "0",
                "latest_time": "now"
            }
            rewritten = rewrite_query_for_spath(spl_query)
            query = rewritten.strip()
            if not (query.startswith("|") or query.startswith("search")):
                query = f"search {query}"

            response = self.service.jobs.oneshot(query, **kwargs)
            reader = results.JSONResultsReader(response)

            rows = []
            for result in reader:
                if isinstance(result, results.Message):
                    continue
                elif isinstance(result, dict):
                    rows.append(result)
            return rows
        except Exception as e:
            print(f"  [SplunkSDK] Search failed: {e}")
            raise

    def test_connection(self):
        """Test connection to Splunk."""
        return self.login()


# ── Fallback: CSV-based client for development ──────────────────

class LocalSplunkClient:
    """
    Drop-in replacement that reads from CSV files
    when Splunk is not available.

    Same interface as SplunkClient so agents don't care
    which one they're talking to.
    """

    INDEX_MAP = {
        "security": "security_logs.csv",
        "infrastructure": "infra_logs.csv",
        "business": "business_logs.csv",
        "compliance": "compliance_logs.csv",
    }

    def __init__(self):
        self.datasets_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "datasets"
        )

    def login(self):
        return True

    def search(self, spl_query, max_results=100):
        """Parse the SPL query to determine which CSV to read."""
        # Extract index name from query
        index_name = None
        for line in spl_query.strip().split("\n"):
            line = line.strip()
            if "index=" in line:
                parts = line.split("index=")
                if len(parts) > 1:
                    raw_index = parts[1].split()[0]
                    # Strip any surrounding quotes or punctuation
                    index_name = raw_index.replace('"', '').replace("'", "").replace(";", "")
                    break

        if not index_name or index_name not in self.INDEX_MAP:
            return []

        csv_file = os.path.join(self.datasets_dir, self.INDEX_MAP[index_name])
        if not os.path.exists(csv_file):
            return []

        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return [row for row in reader][:max_results]

    def test_connection(self):
        return True


def get_client():
    """
    Factory function — returns a real SplunkSDKClient or SplunkClient if credentials
    are configured, otherwise falls back to LocalSplunkClient.
    """
    try:
        from services.env_loader import load_env
        load_env()
    except Exception:
        pass

    password = os.environ.get("SPLUNK_PASSWORD", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    if password or token:
        # Try SDK Client first
        try:
            client = SplunkSDKClient()
            if client.test_connection():
                return client
        except Exception as e:
            print(f"  [Splunk] SDK client connection failed: {e}. Trying REST fallback.")

        # Fall back to REST Client
        try:
            client = SplunkClient()
            if client.test_connection():
                return client
        except Exception as e:
            print(f"  [Splunk] REST client connection failed: {e}")

    print("  [Splunk] Using local CSV fallback")
    return LocalSplunkClient()


if __name__ == "__main__":
    print("\n  Splunk Client Test Connection")
    print("  " + "-" * 50)
    
    client = get_client()
    is_live = type(client).__name__ == "SplunkClient"
    print(f"  Mode: {'Live Splunk Client' if is_live else 'Local CSV Fallback'}")
    
    print("\n  Executing search: index=security ...")
    results = client.search("index=security")
    print(f"  Results found: {len(results)}")
    
    if results:
        print("\n  First matched event:")
        import pprint
        pprint.pprint(dict(results[0]))
    else:
        print("  No events returned.")
    print("  " + "-" * 50 + "\n")
