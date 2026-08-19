"""
Fetch parts of a Chandrayaan-2 IIRS bundle from PRADAN over HTTP byte ranges.

    issdc-iirs --include '*.oat,*.spm' ch2_iir_nci_20201202T1923525130_d_img_d32
    issdc-iirs --bands 10,54,100-110 ch2_iir_nci_20201202T1923525130_d_img_d32

Members are selected by case-insensitive glob against the internal path or the bare file name;
``.qub`` is excluded by default. Bands are read out of the ``.qub`` into a sparse full-size ENVI
cube: band N at its true offset, the bundle's own header kept, unfetched bands reading as zero.
Transfer scales with the highest band requested. Names may also be paths to local zips.

Extracted files are md5-checked against the ``md5_checksum`` in their PDS4 label, where the
bundle publishes one; ``zipfile`` checks every member's CRC32 as it decompresses.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from issdc import ISSDC_PASSWORD, ISSDC_USERNAME, ISSDCRequester, open_remote

# Bytes per bulk read: the range-GET buffer, and the discard size while skipping to a band.
CHUNK = 8 << 20

DEFAULT_EXCLUDE = ("*.qub",)

ENVI_ITEMSIZE = {1: 1, 2: 2, 3: 4, 4: 4, 5: 8, 6: 8, 9: 16, 12: 2, 13: 4, 14: 8, 15: 8}


class ChecksumError(Exception):
    def __init__(self, fname, actual, expected):
        super().__init__(f"Checksum failed for {fname}. Actual: {actual}. Expected: {expected}")


def md5(path, block=1 << 20):
    """md5 hex digest of a file."""
    h = hashlib.md5()  # noqa: S324  -- matching the md5 the archive publishes
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block), b""):
            h.update(chunk)
    return h.hexdigest()


def label_checksums(xml_bytes):
    """{file_name: (md5, size)} for every data file a PDS4 label describes."""
    root = ET.fromstring(xml_bytes)
    out = {}
    for file_el in root.iterfind(".//{*}File"):
        name = file_el.findtext("{*}file_name")
        checksum = file_el.findtext("{*}md5_checksum")
        size = file_el.findtext("{*}file_size")
        if name and checksum:
            out[name.strip()] = (checksum.strip(), int(size) if size else None)
    return out


def verify(paths):
    """
    md5-check files against the labels among `paths`. Returns the number checked.

    Files no extracted label vouches for are skipped. Raises ChecksumError on a mismatch.
    """
    paths = [Path(p) for p in paths]
    expected = {}
    for path in paths:
        if path.suffix.lower() == ".xml":
            try:
                expected.update(label_checksums(path.read_bytes()))
            except ET.ParseError:
                continue
    checked = 0
    for path in paths:
        want = expected.get(path.name)
        if want is None:
            continue
        got = md5(path)
        if got != want[0]:
            raise ChecksumError(path, got, want[0])
        checked += 1
    return checked


def parse_envi_hdr(text):
    """ENVI header text -> {key: value}, values left as strings."""
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith((" ", ";")):
            key, _, val = line.partition("=")
            out[key.strip().lower()] = val.strip()
    return out


def _matches(name, patterns):
    """Case-insensitive glob match against the member path and its basename."""
    name = name.lower()
    base = name.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, p.lower()) or fnmatch.fnmatch(base, p.lower()) for p in patterns)


def select(zf, include=(), exclude=DEFAULT_EXCLUDE):
    """Members matching any `include` glob (empty = all) and no `exclude` glob."""
    return [
        m
        for m in zf.infolist()
        if not m.is_dir() and (not include or _matches(m.filename, include)) and not _matches(m.filename, exclude)
    ]


def fetch_members(zf, out_dir, include=(), exclude=DEFAULT_EXCLUDE):
    """Extract matching members into out_dir, preserving the bundle's internal paths."""
    return [Path(zf.extract(m, out_dir)) for m in select(zf, include, exclude)]


def fetch_bands(zf, out_dir, bands):
    """
    Extract `bands` (1-indexed) from the bundle's .qub into a sparse full-size ENVI cube.

    Returns (path, bytes inflated, cube size). The bundle's .hdr and label are written
    alongside. An existing cube of the right size is filled in place.
    """
    qub = next(m for m in zf.infolist() if m.filename.lower().endswith(".qub"))
    hdrm = next(m for m in zf.infolist() if m.filename.lower().endswith(".hdr"))
    hdr_text = zf.read(hdrm).decode("latin-1")
    hdr = parse_envi_hdr(hdr_text)
    if hdr.get("interleave", "").lower() != "bsq":
        raise ValueError(f"interleave={hdr.get('interleave')}, band extraction assumes bsq")
    plane = int(hdr["samples"]) * int(hdr["lines"]) * ENVI_ITEMSIZE[int(hdr["data type"])]
    n_bands = int(hdr["bands"])
    bands = sorted(set(bands))
    if bands[0] < 1 or bands[-1] > n_bands:
        raise ValueError(f"bands {bands[0]}-{bands[-1]} outside 1-{n_bands}")

    fout = Path(out_dir) / qub.filename
    fout.parent.mkdir(parents=True, exist_ok=True)
    mode = "r+b" if fout.exists() and fout.stat().st_size == n_bands * plane else "wb"
    read = 0
    with zf.open(qub) as src, open(fout, mode) as dst:
        for band in bands:
            skip = (band - 1) * plane - read
            while skip > 0:  # discarded, never held
                got = src.read(min(CHUNK, skip))
                if not got:
                    raise EOFError(f"stream ended while skipping to band {band}")
                skip -= len(got)
                read += len(got)
            buf = src.read(plane)
            if len(buf) != plane:
                raise EOFError(f"short read on band {band}")
            read += plane
            dst.seek((band - 1) * plane)  # the hole before it costs no disk
            dst.write(buf)
        dst.truncate(n_bands * plane)

    fout.with_suffix(".hdr").write_text(
        hdr_text.rstrip("\n") + f"\n;partial cube: bands {','.join(str(b) for b in bands)} fetched, others zero\n"
    )
    label = next((m for m in zf.infolist() if m.filename == str(Path(qub.filename).with_suffix(".xml"))), None)
    if label is not None:
        zf.extract(label, out_dir)
    return fout, read, qub.file_size


def parse_bands(text):
    """
    '10,54,100-110' -> [10, 54, 100, ..., 110].

    >>> parse_bands("3,1,5-7")
    [1, 3, 5, 6, 7]
    """
    out = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):
            lo, _, hi = part.partition("-")
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(part))
    return sorted(out)


def open_bundle(session, name, buffer_size=CHUNK):
    """(ZipFile, size) for a bundle, remote or already on disk. A local path skips the network."""
    path = Path(name)
    if path.exists():
        return zipfile.ZipFile(path), path.stat().st_size
    return open_remote(session, name, buffer_size)


def fetch(names, out_dir="./data", include=(), exclude=DEFAULT_EXCLUDE, bands=None, check=True, session=None):
    """
    Fetch members and/or bands for each bundle in `names`. Returns {name: [paths]}.

    `names` are file ids, URLs, or paths to bundles on disk. Pass an ISSDCRequester as `session`
    to reuse one login; otherwise one is opened for the batch. A remote bundle re-authenticates
    per name and retries once on failure.
    """
    if session is None:
        with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as new_session:
            return fetch(names, out_dir, include, exclude, bands, check, new_session)

    out = {}
    for name in names:
        for attempt in (1, 2):
            try:
                if not Path(name).exists():
                    session.refresh()
                zf, size = open_bundle(session, name)
                with zf:
                    paths = fetch_members(zf, out_dir, include, exclude)
                    got = sum(p.stat().st_size for p in paths)
                    msg = f"{Path(name).stem}: {len(paths)} members ({got / 1e6:.2f} MB) of {size / 1e9:.2f} GB bundle"
                    if check and paths:
                        msg += f", md5 {verify(paths)}/{len(paths)} (rest unlabelled, CRC ok)"
                    if bands:
                        fout, read, full = fetch_bands(zf, out_dir, bands)
                        paths.append(fout)
                        msg += f"; {len(bands)} bands -> {fout.name} (inflated {100 * read / full:.0f}% of cube)"
                out[name] = paths
                print(msg, flush=True)
                break
            except Exception as err:
                if attempt == 1 and not Path(name).exists():
                    print(f"{name}: retrying after {type(err).__name__}", flush=True)
                    continue
                out[name] = []
                print(f"{name}: FAILED {type(err).__name__}: {err}", file=sys.stderr, flush=True)
                break
    return out


# ---------------------------------------------------------------- tests


class _FakeResponse:
    def __init__(self, content=b"", headers=None, status_code=200):
        self.content, self.headers, self.status_code = content, headers or {}, status_code

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
            return _FakeResponse(headers={"content-length": str(len(self.data)), "Accept-Ranges": "bytes"})
        lo, _, hi = headers["Range"].partition("=")[2].partition("-")
        return _FakeResponse(self.data[int(lo) : int(hi) + 1])


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
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        _fake_bundle(Path(tmp) / "bundle.zip")
        with zipfile.ZipFile(Path(tmp) / "bundle.zip") as zf:
            names = lambda **kw: sorted(Path(m.filename).name for m in select(zf, **kw))  # noqa: E731
            assert names() == ["cube.hdr", "cube.oat", "cube.spm", "cube.xml"], names()
            assert names(include=("*.oat", "*.spm")) == ["cube.oat", "cube.spm"]
            assert names(include=("geometry/*",)) == ["cube.oat", "cube.spm"]
            assert names(include=("*.QUB",), exclude=()) == ["cube.qub"]
            assert names(include=("*",), exclude=("*.hdr",)) == ["cube.oat", "cube.qub", "cube.spm", "cube.xml"]
    print("test_select: OK")


def test_fetch_ranged():
    """Members, bands and md5 over the range reader, with no network."""
    import tempfile

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
            assert verify(paths) == 0, "no label extracted, nothing to check"
            assert verify(fetch_members(zf, tmp / "full", include=("*",), exclude=())) == 1

            fout, read, _ = fetch_bands(zf, tmp / "sub", [2, 4])
            assert fout.stat().st_size == len(cube), "full apparent size"
            assert read == 4 * plane, "inflates to the highest band, no further"
            data = fout.read_bytes()
            for band in range(1, 5):
                want = cube[(band - 1) * plane : band * plane] if band in (2, 4) else bytes(plane)
                assert data[(band - 1) * plane : band * plane] == want, f"band {band}"
            hdr = fout.with_suffix(".hdr").read_text()
            assert parse_envi_hdr(hdr)["bands"] == "4" and ";partial" in hdr
            assert fout.with_suffix(".xml").exists(), "label alongside"

            fetch_bands(zf, tmp / "sub", [1])
            data = fout.read_bytes()
            assert data[:plane] == cube[:plane], "new band"
            assert data[plane : 2 * plane] == cube[plane : 2 * plane], "earlier band kept"
            assert data[2 * plane : 3 * plane] == bytes(plane), "untouched band still zero"

        (tmp / "full/data/calibrated/20201202/cube.qub").write_bytes(b"corrupt" + cube[7:])
        try:
            verify([tmp / "full/data/calibrated/20201202" / n for n in ("cube.xml", "cube.qub")])
        except ChecksumError:
            pass
        else:
            raise AssertionError("a corrupted file must fail md5")
    print("test_fetch_ranged: OK")


def test_cli():
    """Argument handling: globs split, bands parse, --no-verify flips check."""
    assert parse_bands("3,1,5-7") == [1, 3, 5, 6, 7]
    calls = []
    real, globals()["fetch"] = fetch, lambda *a: calls.append(a)
    argv = sys.argv
    try:
        sys.argv = ["issdc-iirs", "a", "b", "-o", "/out", "--include", "*.oat, *.spm", "--bands", "1,3-4"]
        main_cli()
        sys.argv = ["issdc-iirs", "a", "--exclude", "", "--no-verify"]
        main_cli()
    finally:
        globals()["fetch"], sys.argv = real, argv
    assert calls[0] == (["a", "b"], "/out", ("*.oat", "*.spm"), ("*.qub",), [1, 3, 4], True), calls[0]
    assert calls[1] == (["a"], "./data", (), (), None, False), calls[1]
    print("test_cli: OK")


def selftest():
    test_select()
    test_fetch_ranged()
    test_cli()


def main_cli():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="IIRS file ids, URLs, or local bundle zips (default: stdin)")
    parser.add_argument("-o", "--out_dir", default="./data", help="output directory (default ./data)")
    parser.add_argument("--include", default="", help="comma-separated globs to fetch (default: all)")
    parser.add_argument("--exclude", default=",".join(DEFAULT_EXCLUDE), help="comma-separated globs to skip")
    parser.add_argument("--bands", help="bands to pull from the .qub, e.g. '10,54,100-110'")
    parser.add_argument("--no-verify", action="store_true", help="skip md5 checks on extracted files")
    parser.add_argument("--selftest", action="store_true", help="run offline tests and exit")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    names = args.names or [line.strip() for line in sys.stdin if line.strip()]
    if not names:
        parser.error("give one or more bundle names, or pipe them on stdin")
    globs = lambda s: tuple(g for g in (p.strip() for p in s.split(",")) if g)  # noqa: E731
    fetch(
        names,
        args.out_dir,
        globs(args.include),
        globs(args.exclude),
        parse_bands(args.bands) if args.bands else None,
        not args.no_verify,
    )


if __name__ == "__main__":
    main_cli()
