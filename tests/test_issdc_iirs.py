"""
Offline self-checks for issdc_iirs.py: globs/select, the range reader against a synthetic
bundle, band-subset extraction, and CLI argument handling. No credentials or network needed.

Run directly: python tests/test_issdc_iirs.py
"""

import hashlib
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import issdc_iirs
from issdc import open_remote
from issdc_iirs import (
    ChecksumError,
    fetch_bands,
    fetch_members,
    parse_bands,
    parse_envi_hdr,
    select,
    verify,
    wavelengths,
)


class _FakeResponse:
    def __init__(self, content=b"", headers=None, status_code=200, url=""):
        self.content, self.headers, self.status_code, self.url = content, headers or {}, status_code, url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        pass


class _FakeSession:
    """Serves HEAD and range GETs out of a local file, as PRADAN does."""

    def __init__(self, path):
        self.data = Path(path).read_bytes()

    def request(self, method, url, headers=None, **kwargs):
        if method.lower() == "head":
            return _FakeResponse(headers={"content-length": str(len(self.data)), "Accept-Ranges": "bytes"}, url=url)
        lo, _, hi = headers["Range"].partition("=")[2].partition("-")
        return _FakeResponse(self.data[int(lo) : int(hi) + 1], url=url)


def _fake_bundle(path, n_bands=4, lines=3, samples=5):
    """A miniature IIRS bundle: BSQ cube, its ENVI header, and a label carrying the real md5."""
    plane = lines * samples * 2
    cube = bytes((7 * i + 1) % 251 for i in range(n_bands * plane))
    hdr = (
        f"ENVI\nsamples = {samples}\nlines = {lines}\nbands = {n_bands}\n"
        "header offset = 0\nfile type = ENVI Standard\ndata type = 12\n"
        "interleave = bsq\nbyte order = 0\n"
    )
    label = (
        '<?xml version="1.0"?><Product_Observational xmlns="http://pds.nasa.gov/pds4/pds/v1">'
        "<File_Area_Observational><File><file_name>cube.qub</file_name>"
        f"<file_size>{len(cube)}</file_size>"
        f"<md5_checksum>{hashlib.md5(cube).hexdigest()}</md5_checksum>"  # noqa: S324
        "</File></File_Area_Observational></Product_Observational>"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data/calibrated/20201202/cube.qub", cube)
        zf.writestr("data/calibrated/20201202/cube.hdr", hdr)
        zf.writestr("data/calibrated/20201202/cube.xml", label)
        zf.writestr("geometry/calibrated/20201202/cube.spm", b"\x00" * 64)
        zf.writestr("geometry/calibrated/20201202/cube.oat", b"orbit attitude\n")
    return cube, plane


def test_select():
    """Globs match the internal path or the basename, and the cube is excluded by default."""
    with tempfile.TemporaryDirectory() as tmp:
        _fake_bundle(Path(tmp) / "bundle.zip")
        with zipfile.ZipFile(Path(tmp) / "bundle.zip") as zf:

            def names(**kw):
                return sorted(Path(m.filename).name for m in select(zf, **kw))

            assert names() == ["cube.hdr", "cube.oat", "cube.spm", "cube.xml"], names()
            assert names(include=("*.oat", "*.spm")) == ["cube.oat", "cube.spm"]
            assert names(include=("geometry/*",)) == ["cube.oat", "cube.spm"]
            assert names(include=("*.QUB",), exclude=()) == ["cube.qub"]
            assert names(include=("*",), exclude=("*.hdr",)) == ["cube.oat", "cube.qub", "cube.spm", "cube.xml"]
    print("test_select: OK")


def test_fetch_ranged():
    """Members, bands and md5 over the range reader, with no network."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cube, plane = _fake_bundle(tmp / "bundle.zip")
        session = _FakeSession(tmp / "bundle.zip")
        zf, size = open_remote(session, "https://x/bundle.zip", buffer_size=512)
        with zf:
            assert size == (tmp / "bundle.zip").stat().st_size

            paths = fetch_members(zf, tmp / "out", include=("*.oat", "*.spm"))
            assert sorted(p.name for p in paths) == ["cube.oat", "cube.spm"]
            assert (tmp / "out/geometry/calibrated/20201202/cube.spm").exists(), "internal paths preserved"
            assert verify(paths) == [], "no label extracted, nothing to check"
            full_paths = fetch_members(zf, tmp / "full", include=("*",), exclude=())
            assert verify(full_paths) == ["cube.qub"], "only the file the label actually vouches for"

            mtime = (tmp / "full/data/calibrated/20201202/cube.qub").stat().st_mtime
            fetch_members(zf, tmp / "full", include=("*",), exclude=())
            assert (tmp / "full/data/calibrated/20201202/cube.qub").stat().st_mtime == mtime, (
                "already on disk: resume skips re-extracting"
            )

            fout, read, _ = fetch_bands(zf, tmp / "sub", [2, 4])
            assert fout.stat().st_size == 2 * plane, "dense: only the requested bands, no holes"
            assert read == 4 * plane, "inflates to the highest band, no further"
            data = fout.read_bytes()
            assert data[:plane] == cube[plane : 2 * plane], "band 2 at dense position 0"
            assert data[plane : 2 * plane] == cube[3 * plane : 4 * plane], "band 4 at dense position 1"
            hdr = fout.with_suffix(".hdr").read_text()
            parsed = parse_envi_hdr(hdr)
            assert parsed["bands"] == "2" and parsed["band names"] == "{2, 4}"
            wl = wavelengths()
            assert parsed["wavelength"] == f"{{{wl[2]:.4f}, {wl[4]:.4f}}}", "true band identity survives the subset"
            assert fout.with_suffix(".xml").exists(), "label alongside"

            fetch_bands(zf, tmp / "sub", [1])
            assert fout.stat().st_size == plane, "a later call is a fresh dense file, not a merge"
            assert fout.read_bytes() == cube[:plane]

        (tmp / "full/data/calibrated/20201202/cube.qub").write_bytes(b"corrupt" + cube[7:])
        try:
            verify([tmp / "full/data/calibrated/20201202" / n for n in ("cube.xml", "cube.qub")])
        except ChecksumError:
            pass
        else:
            raise AssertionError("a corrupted file must fail md5")
    print("test_fetch_ranged: OK")


def test_cli():
    """Argument handling: globs split, bands parse, --no-verify-md5 flips verify_md5."""
    assert parse_bands("3,1,5-7") == [1, 3, 5, 6, 7]
    calls = []
    real_fetch = issdc_iirs.fetch
    issdc_iirs.fetch = lambda *a: calls.append(a)
    argv = sys.argv
    try:
        sys.argv = ["issdc-iirs", "a", "b", "-o", "/out", "--include", "*.oat, *.spm", "--bands", "1,3-4"]
        issdc_iirs.main_cli()
        sys.argv = ["issdc-iirs", "a", "--exclude", "", "--no-verify-md5"]
        issdc_iirs.main_cli()
    finally:
        issdc_iirs.fetch, sys.argv = real_fetch, argv
    assert calls[0] == (["a", "b"], "/out", ("*.oat", "*.spm"), ("*.qub",), [1, 3, 4], True), calls[0]
    assert calls[1] == (["a"], "./data", (), (), None, False), calls[1]
    print("test_cli: OK")


if __name__ == "__main__":
    test_select()
    test_fetch_ranged()
    test_cli()
    print("all issdc_iirs checks passed")
