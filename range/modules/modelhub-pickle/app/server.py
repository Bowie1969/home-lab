#!/usr/bin/env python3
"""Model hub endpoint — OpenAI-compatible model management with unsafe pickle loading.

Deliberately vulnerable: model blobs uploaded via /v1/models are loaded with
pickle.loads (no picklescan, no sandbox). A crafted .bin triggers arbitrary
code execution as the `hive` user. The GGUF loader trusts attacker-supplied
tensor dimensions, leaking adjacent heap contents.

Stdlib-only — runs inside the Keystone rootless podman container with no
internet access.
"""
import http.server
import json
import os
import pickle
import struct
import sys
import tempfile

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "11435"))
MODELS_DIR = "/app/models"
REGISTRY_DIR = "/app/registry"

_loaded_models: dict[str, dict] = {}


def _unsafe_load_model(data: bytes, name: str) -> dict:
    """Load a model blob — deliberately unsafe pickle path."""
    if data[:4] == b"GGUF":
        return _parse_gguf(data, name)
    return {"name": name, "loaded_via": "pickle", "result": repr(pickle.loads(data))}


def _parse_gguf(data: bytes, name: str) -> dict:
    """Parse GGUF header — trusts tensor dimensions from the file (heap leak)."""
    if len(data) < 24:
        return {"error": "truncated GGUF header"}
    magic, version, n_tensors, n_kv = struct.unpack_from("<4sIQQ", data, 0)
    leak_size = min(n_tensors * 8, 4096)
    leaked = data[24:24 + leak_size]
    return {
        "name": name,
        "loaded_via": "gguf",
        "version": version,
        "n_tensors": n_tensors,
        "n_kv": n_kv,
        "tensor_preview_hex": leaked.hex()[:256],
    }


class ModelHubHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            models = list(_loaded_models.keys())
            self._json_response(200, {"object": "list", "data": [
                {"id": m, "object": "model"} for m in models
            ]})
        elif self.path.startswith("/v1/models/"):
            name = self.path.split("/v1/models/", 1)[1]
            if name in _loaded_models:
                self._json_response(200, _loaded_models[name])
            else:
                self._json_response(404, {"error": f"model {name!r} not found"})
        elif self.path == "/health":
            self._json_response(200, {"status": "ok"})
        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/v1/models":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            name = self.headers.get("X-Model-Name", "unnamed")
            blob_path = os.path.join(REGISTRY_DIR, name)
            with open(blob_path, "wb") as f:
                f.write(body)
            result = _unsafe_load_model(body, name)
            _loaded_models[name] = result
            self._json_response(200, {"uploaded": name, "size": length, "load_result": result})
        else:
            self._json_response(404, {"error": "not found"})

    do_PUT = do_POST

    def _json_response(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REGISTRY_DIR, exist_ok=True)
    server = http.server.HTTPServer((HOST, PORT), ModelHubHandler)
    print(f"modelhub listening on {HOST}:{PORT}", file=sys.stderr)
    server.serve_forever()
