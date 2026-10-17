"""Guard the remote adapter's credential transport boundary."""

import importlib.util
from pathlib import Path
import unittest


ADAPTER = Path(__file__).resolve().parents[2] / "scripts/cairn-remote-stdio.py"
spec = importlib.util.spec_from_file_location("cairn_remote_stdio", ADAPTER)
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class RemoteStdioTests(unittest.TestCase):
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
