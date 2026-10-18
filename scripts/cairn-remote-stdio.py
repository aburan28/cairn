#!/usr/bin/env python3
"""Connect a stdio MCP client to an authenticated Cairn Streamable HTTP URL."""

import argparse
import base64
import http.client
import json
import os
import re
import sys
from urllib.parse import urlsplit


MAX_FRAME = 16 << 20


def endpoint(url, allow_loopback_http):
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path != "/mcp":
        raise ValueError("use a URL ending in /mcp without embedded credentials or query")
    if parsed.scheme == "https" and parsed.hostname:
        return parsed
    if (allow_loopback_http and parsed.scheme == "http"
            and parsed.hostname in ("127.0.0.1", "localhost", "::1")):
        return parsed
    raise ValueError("remote Cairn MCP requires HTTPS; loopback HTTP is for local tests only")


def rpc_error(identifier, message):
    return {"jsonrpc": "2.0", "id": identifier,
            "error": {"code": -32000, "message": message}}


def run(url, allow_loopback_http=False):
    address = endpoint(url, allow_loopback_http)
    token = os.environ.get("CAIRN_MCP_BEARER_TOKEN")
    username = os.environ.get("CAIRN_MCP_USER")
    password = os.environ.get("CAIRN_MCP_PASSWORD")
    if token:
        if username or password:
            raise ValueError("choose a bearer token or Basic credentials, not both")
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("CAIRN_MCP_BEARER_TOKEN must be 64 lowercase hexadecimal characters")
        authorization = f"Bearer {token}"
    else:
        if not username or not password or ":" in username:
            raise ValueError("set CAIRN_MCP_BEARER_TOKEN or CAIRN_MCP_USER and CAIRN_MCP_PASSWORD")
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        authorization = f"Basic {encoded}"
    timeout = int(os.environ.get("CAIRN_MCP_TIMEOUT_SECONDS", "3600"))
    if timeout < 1:
        raise ValueError("CAIRN_MCP_TIMEOUT_SECONDS must be positive")
    session = None
    while raw := sys.stdin.buffer.readline(MAX_FRAME + 2):
        if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
            raise ValueError("MCP frame exceeds 16 MiB or is not newline terminated")
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("MCP frame must be one JSON object")
        except (ValueError, UnicodeDecodeError) as error:
            sys.stdout.write(json.dumps(rpc_error(None, str(error))) + "\n")
            sys.stdout.flush()
            continue
        identifier = value.get("id")
        method = value.get("method")
        if method == "initialize":
            session = None
        headers = {
            "Authorization": authorization,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if session:
            headers["Mcp-Session-Id"] = session
            headers["MCP-Protocol-Version"] = "2025-06-18"
        connection_type = (http.client.HTTPSConnection if address.scheme == "https"
                           else http.client.HTTPConnection)
        connection = connection_type(address.hostname, address.port, timeout=timeout)
        try:
            connection.request("POST", "/mcp", body=raw.rstrip(b"\n"), headers=headers)
            response = connection.getresponse()
            body = response.read(MAX_FRAME + 1)
            if len(body) > MAX_FRAME:
                raise ValueError("remote MCP response exceeds 16 MiB")
            if method == "initialize" and response.status == 200:
                candidate = response.getheader("Mcp-Session-Id")
                if not candidate or not re.fullmatch(r"[!-~]{1,256}", candidate):
                    raise ValueError("remote MCP initialize lacked a valid session id")
                session = candidate
            if response.status == 202 and identifier is None:
                continue
            if response.status != 200:
                if identifier is None:
                    print(f"cairn remote MCP: HTTP {response.status}", file=sys.stderr)
                    continue
                frame = rpc_error(identifier, f"remote Cairn MCP returned HTTP {response.status}")
            else:
                frame = json.loads(body)
                if not isinstance(frame, dict) or frame.get("jsonrpc") != "2.0":
                    raise ValueError("remote MCP response is not JSON-RPC 2.0")
            if identifier is not None:
                sys.stdout.write(json.dumps(frame, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except (OSError, ValueError, http.client.HTTPException) as error:
            if identifier is not None:
                sys.stdout.write(json.dumps(rpc_error(identifier, str(error))) + "\n")
                sys.stdout.flush()
            else:
                print(f"cairn remote MCP: {error}", file=sys.stderr)
        finally:
            connection.close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="https://your-cairn-host/mcp")
    parser.add_argument("--allow-loopback-http", action="store_true",
                        help="local test only; public HTTP is refused")
    args = parser.parse_args(argv)
    try:
        return run(args.url, args.allow_loopback_http)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
