"""Assert-based self-check for issdc's dead-session handling.

Covers: the total_size==0 stub-guard in _download, and the SessionExpired
redirect check in download(). Run directly: python tests/test_stub_guard.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from issdc import IDP_HOST, SessionExpired, _download, download


class FakeResponse:
    def __init__(self, url, headers=None, status_code=200):
        self.url = url
        self.headers = headers or {}
        self.status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    """Stands in for ISSDCRequester: only `.request("head", url)` is exercised here."""

    def __init__(self, response_url, headers=None, status_code=200):
        self.response_url = response_url
        self.headers = headers
        self.status_code = status_code

    def request(self, method, url, **kwargs):
        assert method == "head"
        return FakeResponse(self.response_url, self.headers, self.status_code)


def test_real_file_survives_dead_session_response(tmp_path):
    fp = tmp_path / "ch2_iir_nri_real.zip"
    fp.write_bytes(b"real zip bytes")
    _download(None, str(fp.name), tmp_path, total_size=0, byte_range_support=False)
    assert fp.exists() and fp.read_bytes() == b"real zip bytes"


def test_empty_stub_is_removed(tmp_path):
    fp = tmp_path / "ch2_iir_nri_stub.zip"
    fp.write_bytes(b"")
    _download(None, str(fp.name), tmp_path, total_size=0, byte_range_support=False)
    assert not fp.exists()


def test_missing_file_stays_missing(tmp_path):
    fp = tmp_path / "ch2_iir_nri_never_downloaded.zip"
    _download(None, str(fp.name), tmp_path, total_size=0, byte_range_support=False)
    assert not fp.exists()


def test_idp_redirect_raises_session_expired(tmp_path):
    session = FakeSession(f"https://{IDP_HOST}/auth/realms/issdc/protocol/openid-connect/auth?...")
    try:
        download(session, "ch2_iir_nri_real.zip?iirs", tmp_path)
        raise AssertionError("expected SessionExpired")
    except SessionExpired:
        pass


def test_genuine_401_does_not_raise_session_expired(tmp_path):
    session = FakeSession("https://pradan.issdc.gov.in/ch2/protected/downloadData/.../bogus.zip?iirs", status_code=401)
    _download(session, "ch2_iir_nri_bogus.zip?iirs", tmp_path, total_size=0, byte_range_support=False)


def test_head_403_raises_session_expired(tmp_path):
    """The dead-session shape actually seen in production: HEAD 403, no redirect."""
    session = FakeSession("https://pradan.issdc.gov.in/ch2/protected/downloadData/.../real.zip?iirs", status_code=403)
    try:
        download(session, "ch2_iir_nri_real.zip?iirs", tmp_path)
        raise AssertionError("expected SessionExpired")
    except SessionExpired:
        pass


if __name__ == "__main__":
    import shutil
    import tempfile

    for fn in (
        test_real_file_survives_dead_session_response,
        test_empty_stub_is_removed,
        test_missing_file_stays_missing,
        test_idp_redirect_raises_session_expired,
        test_genuine_401_does_not_raise_session_expired,
        test_head_403_raises_session_expired,
    ):
        d = Path(tempfile.mkdtemp())
        try:
            fn(d)
            print(f"ok: {fn.__name__}")
        finally:
            shutil.rmtree(d)
    print("all checks passed")
