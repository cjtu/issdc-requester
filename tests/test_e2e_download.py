"""
End-to-end smoke test against the real PRADAN server: downloads real files.

Needs ISSDC credentials (.env) and network access. For every PRADAN instrument tag (the
`?instrument` suffix) in issdc_test_urls.txt, downloads only the *smallest* example -- the
curated list runs from a few KB up to multi-GB (one IIRS bundle alone is 9.7 GB, one SPICE
attitude kernel is 5.2 GB), and a smoke test only needs proof that download works for each
instrument, not every example. IIRS is excluded here entirely: test_iirs_partial_fetch already
proves the ancillary+band-subset path against a real bundle without ever pulling the full
thing, which is the whole point of issdc_iirs.py.

Not part of the offline test suite (test_issdc_iirs.py, test_issdc_index.py,
test_stub_guard.py); run manually when you have credentials and network to spare:

    python tests/test_e2e_download.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from issdc import ISSDC_PASSWORD, ISSDC_USERNAME, ISSDCRequester, download, read_file_paths
from issdc_iirs import fetch as fetch_iirs

URLS_FILE = Path(__file__).parent / "issdc_test_urls.txt"


def smallest_per_instrument(urls, session, only=None):
    """{instrument_tag: (url, size)}, the smallest URL per `?instrument` tag in `urls`.

    Pass `only` to HEAD just that one tag's URLs instead of the whole list.
    """
    best = {}
    for url in urls:
        instrument = url.rsplit("?", 1)[-1]
        if only is not None and instrument != only:
            continue
        with session.request("HEAD", url) as resp:
            size = int(resp.headers.get("content-length", 0))
        if instrument not in best or size < best[instrument][1]:
            best[instrument] = (url, size)
    return best


def test_full_downloads(out_dir):
    """The smallest real file per instrument downloads and matches its HEAD size."""
    urls = read_file_paths(URLS_FILE)
    with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session:
        picks = smallest_per_instrument(urls, session)
        picks.pop("iirs", None)  # covered by test_iirs_partial_fetch instead
        for instrument, (url, expected_size) in sorted(picks.items()):
            download(session, url, str(out_dir))

            fname = Path(url.split("?")[0]).name
            fpath = Path(out_dir) / fname
            assert fpath.exists(), f"File {fpath} not found"
            assert fpath.stat().st_size == expected_size, (
                f"Size mismatch for {fname}: expected {expected_size}, got {fpath.stat().st_size}"
            )
            print(f"ok: {instrument} -> {fname} ({expected_size / 1e6:.1f} MB)")
    print("test_full_downloads: OK")


def test_iirs_partial_fetch(out_dir):
    """The smallest IIRS bundle: ancillary files + a band subset, no full-bundle download."""
    urls = read_file_paths(URLS_FILE)
    with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session:
        iirs_url, _ = smallest_per_instrument(urls, session, only="iirs")["iirs"]
    result = fetch_iirs([iirs_url], out_dir=str(out_dir), include=("*.spm", "*.oat"), bands=[1, 54])
    paths = result[iirs_url]
    assert paths, f"no files fetched for {iirs_url}"
    for p in paths:
        assert p.exists(), f"missing {p}"
    print(f"ok: iirs partial fetch -> {sorted(p.name for p in paths)}")
    print("test_iirs_partial_fetch: OK")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_full_downloads(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_iirs_partial_fetch(Path(d))
    print("all e2e checks passed")
