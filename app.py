import json, os, socket, ipaddress
from urllib.parse import urljoin, urlparse, unquote
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-d1d2e55fc4"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
REDIRECT_LIMIT = 5

# ---------- helpers ----------
def is_public_ip(host):
    """True if host resolves ONLY to public IPs."""
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
    """Fully resolve a path, rejecting null bytes."""
    if '\0' in path:
        raise ValueError("null byte in path")
    # Expand ~ and $HOME
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        abs_path = os.path.abspath(expanded)
    else:
        abs_path = expanded
    # Resolve symlinks and ..
    return os.path.realpath(abs_path)

def recursive_unquote(s):
    """Decode percent-encoding repeatedly until the string stops changing."""
    prev = None
    while prev != s:
        prev = s
        s = unquote(s)
    return s

# ---------- read_file ----------
def read_file(args):
    raw_path = args.get("path", "")
    # Fully decode (handles %252e%252e%252f → ../)
    fully_decoded = recursive_unquote(raw_path)

    # Make absolute relative to sandbox root (if not already absolute)
    if not os.path.isabs(fully_decoded):
        decoded_abs = os.path.join(SANDBOX_ROOT, fully_decoded)
    else:
        decoded_abs = fully_decoded

    # Resolve all .. and symlinks
    try:
        real_decoded = canonicalize_path(decoded_abs)
    except Exception as e:
        return {"action": "block", "reason": f"Path error: {e}", "result": None}

    # Boundary check – must be INSIDE the sandbox (or the sandbox root itself)
    if real_decoded == SANDBOX_ROOT or real_decoded.startswith(SANDBOX_ROOT + os.sep):
        pass   # inside
    else:
        return {"action": "block", "reason": f"Path resolves outside sandbox: {real_decoded}", "result": None}

    # Now open the *raw* path (to support literal %2e%2e filenames)
    if not os.path.isabs(raw_path):
        raw_abs = os.path.join(SANDBOX_ROOT, raw_path)
    else:
        raw_abs = raw_path

    try:
        real_raw = canonicalize_path(raw_abs)
    except Exception as e:
        return {"action": "block", "reason": f"Raw path error: {e}", "result": None}

    if not (real_raw == SANDBOX_ROOT or real_raw.startswith(SANDBOX_ROOT + os.sep)):
        return {"action": "block", "reason": f"Raw path escapes sandbox: {real_raw}", "result": None}

    try:
        with open(real_raw, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return {"action": "allow", "reason": "File inside sandbox.", "result": content}
    except Exception as e:
        return {"action": "allow", "reason": "File inside sandbox, but error reading.", "result": f"Error: {e}"}

# ---------- fetch_url ----------
def fetch_url(args):
    url = args.get("url", "")
    # 1. Parse and validate scheme
    try:
        parsed = urlparse(url)
    except:
        return {"action": "block", "reason": "Malformed URL.", "result": None}
    if parsed.scheme not in ("http", "https"):
        return {"action": "block", "reason": f"Scheme {parsed.scheme} not allowed.", "result": None}
    if parsed.username or parsed.password:
        return {"action": "block", "reason": "URL contains userinfo.", "result": None}

    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "No hostname in URL.", "result": None}
    if hostname.lower() not in ALLOWED_HOSTS:
        return {"action": "block", "reason": f"Host {hostname} not allowed.", "result": None}
    if not is_public_ip(hostname):
        return {"action": "block", "reason": "Host resolves to non‑public IP.", "result": None}

    # 2. Follow redirects, re‑validating every hop
    current_url = url
    for _ in range(REDIRECT_LIMIT + 1):
        try:
            resp = requests.get(current_url, timeout=5, allow_redirects=False, stream=True)
        except Exception as e:
            return {"action": "block", "reason": f"Fetch error: {e}", "result": None}

        if resp.is_redirect:
            new_url = resp.headers.get("Location", "")
            if not new_url:
                return {"action": "block", "reason": "Redirect missing Location.", "result": None}
            new_url = urljoin(current_url, new_url)
            # Re‑parse the redirect target
            try:
                new_parsed = urlparse(new_url)
            except:
                return {"action": "block", "reason": "Redirect URL malformed.", "result": None}
            # Scheme must remain http/https
            if new_parsed.scheme not in ("http", "https"):
                return {"action": "block", "reason": f"Redirect to disallowed scheme {new_parsed.scheme}.", "result": None}
            # No credentials in redirect
            if new_parsed.username or new_parsed.password:
                return {"action": "block", "reason": "Redirect contains userinfo.", "result": None}
            # Hostname must still be in allowlist (case‑insensitive)
            new_host = new_parsed.hostname
            if not new_host or new_host.lower() not in ALLOWED_HOSTS:
                return {"action": "block", "reason": f"Redirect to forbidden host: {new_host}", "result": None}
            # The new host must resolve to a public IP (prevents DNS rebinding)
            if not is_public_ip(new_host):
                return {"action": "block", "reason": "Redirect host resolves to non‑public IP.", "result": None}
            current_url = new_url
        else:
            # Not a redirect – success
            return {"action": "allow", "reason": "Fetched successfully.", "result": resp.text}

    return {"action": "block", "reason": "Too many redirects.", "result": None}

# ---------- Main endpoint ----------
@app.route("/", methods=["POST"])
def guardrail():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"action": "block", "reason": "Invalid JSON.", "result": None})
    tool = data.get("tool")
    args = data.get("arguments", {})
    if tool == "read_file":
        return jsonify(read_file(args))
    elif tool == "fetch_url":
        return jsonify(fetch_url(args))
    else:
        return jsonify({"action": "block", "reason": "Unknown tool.", "result": None})

# ---------- Debug endpoint ----------
@app.route("/debug", methods=["POST"])
def debug():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"})
    tool = data.get("tool")
    args = data.get("arguments", {})
    info = {"tool": tool, "args": args}
    try:
        if tool == "read_file":
            res = read_file(args)
        elif tool == "fetch_url":
            res = fetch_url(args)
        else:
            res = {"action": "block", "reason": "Unknown tool."}
    except Exception as e:
        res = {"action": "block", "reason": f"Crash: {e}"}
    info["decision"] = res
    return jsonify(info)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
