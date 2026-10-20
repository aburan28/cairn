"""Guard the remote adapter's credential transport boundary."""

import importlib.util
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ADAPTER = Path(__file__).resolve().parents[2] / "scripts/cairn-remote-stdio.py"
spec = importlib.util.spec_from_file_location("cairn_remote_stdio", ADAPTER)
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class RemoteStdioTests(unittest.TestCase):
    def test_missing_python_roots_use_system_bundle_with_verification(self):
        with patch.object(remote.ssl, "get_default_verify_paths", return_value=SimpleNamespace(
                cafile=None, capath=None)), patch.object(remote.os.path, "isfile", return_value=True), \
                patch.object(remote.ssl, "create_default_context") as context, \
                patch.dict(os.environ, {"SSL_CERT_FILE": "", "SSL_CERT_DIR": ""}):
            remote.tls_context()
        context.assert_called_once_with(cafile="/etc/ssl/cert.pem")

    def test_explicit_ca_selection_is_honored(self):
        with patch.object(remote.ssl, "get_default_verify_paths", return_value=SimpleNamespace(
                cafile=None, capath=None)), patch.object(remote.ssl, "create_default_context") as context, \
                patch.dict(os.environ, {"SSL_CERT_FILE": "/chosen/ca.pem"}):
            remote.tls_context()
        context.assert_called_once_with()

    def test_credentials_cannot_be_sent_to_plaintext_or_redirect_url(self):
        for url in ("http://public.example/mcp", "https://user:pass@public.example/mcp",
                    "https://public.example/mcp?next=other", "https://public.example/other"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                remote.endpoint(url, allow_loopback_http=False)
        self.assertEqual(remote.endpoint("https://public.example/mcp", False).scheme,
                         "https")
        self.assertEqual(remote.endpoint("http://127.0.0.1:8001/mcp", True).hostname,
                         "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
