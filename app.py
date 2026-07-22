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
    """True only if ALL resolved IPs are globally routable (no private/loopback/link-local/unspecified/IPv4-mapped)."""
    try:
        addrinfo = socket.getaddrinfo(host, None)
        ips = {info[4][0] for info in addrinfo}
        for ip_str in ips:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                return False
        return True
    except:
        return False

def canonicalize_path(path):
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    if '\0' in path:
        raise ValueError("null byte in path")
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        abs_path = os.path.abspath(expanded)
    else:
        abs_path = expanded
    return os.path.realpath(abs_path)

def recursive_unquote(s):
    if not isinstance(s, str):
        return ""
    prev = None
    while prev != s:
        prev = s
        s = unquote(s)
    return s

def has_traversal(path):
    """True if the normalized path contains a '..' component (not just substring)."""
    # Normalize slashes and split
    parts = path.replace('\\', '/').split('/')
    return '..' in parts

# ---------- read_file ----------
def read_file(args):
    raw_path = args.get("path", "")
    if not isinstance(raw_path, str):
        return {"action": "block", "reason": "path must be a string.", "result": None}

    fully_decoded = recursive_unquote(raw_path)

    # Block only if '..' is a whole path component (traversal)
    if has_traversal(fully_decoded):
        return {"action": "block", "reason": "Path traversal (..) detected.", "result": None}

    if not os.path.isabs(fully_decoded):
        decoded_abs = os.path.join(SANDBOX_ROOT, fully_decoded)
    else:
        decoded_abs = fully_decoded

    try:
        real_decoded = canonicalize_path(decoded_abs)
    except Exception as e:
        return {"action": "block", "reason": f"Path error: {e}", "result": None}

    if not (real_decoded == SANDBOX_ROOT or real_decoded.startswith(SANDBOX_ROOT + os.sep)):
        return {"action": "block", "reason": f"Path resolves outside sandbox: {real_decoded}", "result": None}

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
    if not isinstance(url, str):
        return {"action": "block", "reason": "url must be a string.", "result": None}

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
            try:
                new_parsed = urlparse(new_url)
            except:
                return {"action": "block", "reason": "Redirect URL malformed.", "result": None}
            if new_parsed.scheme not in ("http", "https"):
                return {"action": "block", "reason": f"Redirect to disallowed scheme {new_parsed.scheme}.", "result": None}
            if new_parsed.username or new_parsed.password:
                return {"action": "block", "reason": "Redirect contains userinfo.", "result": None}
            new_host = new_parsed.hostname
            if not new_host or new_host.lower() not in ALLOWED_HOSTS:
                return {"action": "block", "reason": f"Redirect to forbidden host: {new_host}", "result": None}
            if not is_public_ip(new_host):
                return {"action": "block", "reason": "Redirect host resolves to non‑public IP.", "result": None}
            current_url = new_url
        else:
            return {"action": "allow", "reason": "Fetched successfully.", "result": resp.text}

    return {"action": "block", "reason": "Too many redirects.", "result": None}

# ---------- Main endpoint ----------
@app.route("/", methods=["POST"])
def guardrail():
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"action": "block", "reason": "Invalid JSON.", "result": None})
        tool = data.get("tool")
        args = data.get("arguments", {})
        if tool == "read_file":
            result = read_file(args)
        elif tool == "fetch_url":
            result = fetch_url(args)
        else:
            result = {"action": "block", "reason": "Unknown tool.", "result": None}
        return jsonify(result)
    except Exception as e:
        return jsonify({"action": "block", "reason": f"Internal error: {e}", "result": None})

# ---------- Debug endpoint ----------
@app.route("/debug", methods=["POST"])
def debug():
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON"})
        tool = data.get("tool")
        args = data.get("arguments", {})
        info = {"tool": tool, "args": args}
        if tool == "read_file":
            raw = args.get("path", "")
            dec = recursive_unquote(raw)
            abs_dec = os.path.join(SANDBOX_ROOT, dec) if not os.path.isabs(dec) else dec
            real_dec = canonicalize_path(abs_dec) if isinstance(raw, str) else None
            info["decoded"] = dec
            info["absolute_decoded"] = abs_dec
            info["real_decoded"] = real_dec
            info["has_traversal"] = has_traversal(dec)
            res = read_file(args)
        elif tool == "fetch_url":
            url = args.get("url", "")
            parsed = urlparse(url) if isinstance(url, str) else None
            info["parsed"] = str(parsed) if parsed else None
            info["hostname"] = parsed.hostname if parsed else None
            res = fetch_url(args)
        else:
            res = {"action": "block", "reason": "Unknown tool."}
        info["decision"] = res
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
