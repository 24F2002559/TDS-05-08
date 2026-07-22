import json, os, socket, ipaddress
from urllib.parse import urljoin, urlparse, unquote
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-d1d2e55fc4"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
REDIRECT_LIMIT = 5

def is_public_ip(host):
    try:
        addrinfo = socket.getaddrinfo(host, None)
        ips = {info[4][0] for info in addrinfo}
        for ip_str in ips:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        return True
    except:
        return False

def canonicalize_path(path):
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        abs_path = os.path.abspath(expanded)
    else:
        abs_path = expanded
    return os.path.realpath(abs_path)

def read_file(args):
    path = args.get("path", "")
    # Decode percent-encoded characters to catch evasion like %2e%2e -> ..
    decoded_path = unquote(path)
    # Make decoded path absolute relative to sandbox root
    if not os.path.isabs(decoded_path):
        decoded_abs = os.path.join(SANDBOX_ROOT, decoded_path)
    else:
        decoded_abs = decoded_path
    real_decoded = canonicalize_path(decoded_abs)
    if not (real_decoded == SANDBOX_ROOT or real_decoded.startswith(SANDBOX_ROOT + os.sep)):
        return {"action": "block", "reason": f"Path resolves outside sandbox: {real_decoded}", "result": None}

    # The decoded path is safe; now process the original raw path for actual file access
    raw_path = path
    if not os.path.isabs(raw_path):
        raw_abs = os.path.join(SANDBOX_ROOT, raw_path)
    else:
        raw_abs = raw_path
    real_raw = canonicalize_path(raw_abs)
    # Extra safety: raw path must also be inside sandbox (should always be true here)
    if not (real_raw == SANDBOX_ROOT or real_raw.startswith(SANDBOX_ROOT + os.sep)):
        return {"action": "block", "reason": f"Raw path escapes sandbox: {real_raw}", "result": None}

    try:
        with open(real_raw, 'r') as f:
            content = f.read()
        return {"action": "allow", "reason": "File inside sandbox.", "result": content}
    except Exception as e:
        return {"action": "allow", "reason": "File inside sandbox, but error reading.", "result": f"Error: {e}"}

def fetch_url(args):
    url = args.get("url", "")
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        return {"action": "block", "reason": "URL contains userinfo.", "result": None}
    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "No hostname in URL.", "result": None}
    # Case-insensitive hostname check
    if hostname.lower() not in ALLOWED_HOSTS:
        return {"action": "block", "reason": f"Host {hostname} not allowed.", "result": None}

    current_url = url
    for _ in range(REDIRECT_LIMIT + 1):
        if not is_public_ip(urlparse(current_url).hostname):
            return {"action": "block", "reason": "Host resolves to non‑public IP.", "result": None}
        try:
            resp = requests.get(current_url, timeout=5, allow_redirects=False, stream=True)
        except Exception as e:
            return {"action": "block", "reason": f"Fetch error: {e}", "result": None}
        if resp.is_redirect:
            new_url = resp.headers.get("Location")
            if not new_url:
                return {"action": "block", "reason": "Redirect missing Location.", "result": None}
            new_url = urljoin(current_url, new_url)
            new_parsed = urlparse(new_url)
            if new_parsed.username or new_parsed.password:
                return {"action": "block", "reason": "Redirect contains userinfo.", "result": None}
            if new_parsed.hostname and new_parsed.hostname.lower() not in ALLOWED_HOSTS:
                return {"action": "block", "reason": f"Redirect to forbidden host: {new_parsed.hostname}", "result": None}
            current_url = new_url
        else:
            return {"action": "allow", "reason": "Fetched successfully.", "result": resp.text}
    return {"action": "block", "reason": "Too many redirects.", "result": None}

@app.route("/", methods=["POST"])
def guardrail():
    data = request.get_json()
    tool = data.get("tool")
    args = data.get("arguments", {})
    if tool == "read_file":
        return jsonify(read_file(args))
    elif tool == "fetch_url":
        return jsonify(fetch_url(args))
    else:
        return jsonify({"action": "block", "reason": "Unknown tool.", "result": None})

if __name__ == "__main__":
    app.run()
