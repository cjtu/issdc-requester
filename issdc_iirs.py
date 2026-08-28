"""
Fetch parts of a Chandrayaan-2 IIRS bundle from PRADAN over HTTP byte ranges.

    issdc-iirs --include '*.oat,*.spm' ch2_iir_nci_20201202T1923525130_d_img_d32
    issdc-iirs --bands 10,54,100-110 ch2_iir_nci_20201202T1923525130_d_img_d32

Members are selected by case-insensitive glob against the internal path or the bare file name;
``.qub`` is excluded by default. Bands are read out of the ``.qub`` into a compact ENVI cube,with
``band names`` and ``wavelength`` (nm) specify the downloaded bands. Download cost scales with the
highest band requested (need to inflate BSQ zip sequentially). Names can be paths to local zips.

Extracted files are md5-checked against the ``md5_checksum`` in their PDS4 label, where available.
``zipfile`` checks every member's CRC32 as it decompresses.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from issdc import ISSDC_PASSWORD, ISSDC_USERNAME, ISSDCRequester, SessionExpired, open_remote

# Bytes per bulk read: the range-GET buffer, and the discard size while skipping to a band.
CHUNK = 8 << 20

DEFAULT_EXCLUDE = ("*.qub",)

ENVI_ITEMSIZE = {1: 1, 2: 2, 3: 4, 4: 4, 5: 8, 6: 8, 9: 16, 12: 2, 13: 4, 14: 8, 15: 8}

# IIRS 256-band centre-wavelength table (nm)
WAVELENGTHS_CSV = Path(__file__).parent / "resources" / "ch2_iirs_wavelengths.csv"


def wavelengths():
    """{band_number: centre_wavelength_nm} from the packaged IIRS band table."""
    with open(WAVELENGTHS_CSV, newline="") as f:
        return {int(row["band_number"]): float(row["center_wavelength"]) for row in csv.DictReader(f)}


class ChecksumError(Exception):
    def __init__(self, fname, actual, expected):
        super().__init__(f"Checksum failed for {fname}. Actual: {actual}. Expected: {expected}")


def md5(path, block=1 << 20):
    """Return md5 hex digest of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block), b""):
            h.update(chunk)
    return h.hexdigest()


def label_checksums(xml_bytes):
    """Return {file_name: md5} for every data file a PDS4 label describes."""
    root = ET.fromstring(xml_bytes)
    out = {}
    for file_el in root.iterfind(".//{*}File"):
        name = file_el.findtext("{*}file_name")
        checksum = file_el.findtext("{*}md5_checksum")
        if name and checksum:
            out[name.strip()] = checksum.strip()
    return out


def verify(paths):
    """
    Return names of md5-checked files against the md5 labels among `paths`.

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
    checked = []
    for path in paths:
        want = expected.get(path.name)
        if want is None:
            continue
        got = md5(path)
        if got != want:
            raise ChecksumError(path, got, want)
        checked.append(path.name)
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
    """Extract matching members into out_dir, preserving the bundle's internal paths.

    A member whose target file already exists is skipped. Safe to resume, no re-download.
    """
    paths = []
    for m in select(zf, include, exclude):
        target = Path(out_dir) / m.filename
        if not target.exists():
            zf.extract(m, out_dir)
        paths.append(target)
    return paths


def fetch_bands(zf, out_dir, bands):
    """
    Extract `bands` (1-indexed) from the bundle's .qub into a compact ENVI cube.

    Bands are packed densely in request order. Header has `band names` and `wavelength` (nm).
    Re-running with a different band set re-fetches everything and overwrites previous cube.

    Returns (path, bytes inflated, cube size). Header is written alongside.
    """
    qub = next(m for m in zf.infolist() if m.filename.lower().endswith(".qub"))
    hdrm = next(m for m in zf.infolist() if m.filename.lower().endswith(".hdr"))
    hdr = parse_envi_hdr(zf.read(hdrm).decode("latin-1"))
    if hdr.get("interleave", "").lower() != "bsq":
        raise ValueError(f"interleave={hdr.get('interleave')}, band extraction assumes bsq")
    plane = int(hdr["samples"]) * int(hdr["lines"]) * ENVI_ITEMSIZE[int(hdr["data type"])]
    n_bands = int(hdr["bands"])
    bands = sorted(set(bands))
    if bands[0] < 1 or bands[-1] > n_bands:
        raise ValueError(f"bands {bands[0]}-{bands[-1]} outside 1-{n_bands}")

    fout = Path(out_dir) / qub.filename
    fout.parent.mkdir(parents=True, exist_ok=True)
    read = 0
    with zf.open(qub) as src, open(fout, "wb") as dst:
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
            dst.write(buf)  # dense: appended at its position in `bands`, not its true offset

    wl = wavelengths()
    fout.with_suffix(".hdr").write_text(
        f"ENVI\nsamples = {hdr['samples']}\nlines = {hdr['lines']}\nbands = {len(bands)}\n"
        "header offset = 0\nfile type = ENVI Standard\n"
        f"data type = {hdr['data type']}\ninterleave = bsq\nbyte order = {hdr.get('byte order', 0)}\n"
        "wavelength units = Nanometers\n"
        "band names = {" + ", ".join(str(b) for b in bands) + "}\n"
        "wavelength = {" + ", ".join(f"{wl[b]:.4f}" for b in bands) + "}\n"
        "description = {" + f"IIRS band subset: {len(bands)} of {n_bands} bands, "
        "see band names for included bands}\n"
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


def fetch(names, out_dir="./data", include=(), exclude=DEFAULT_EXCLUDE, bands=None, verify_md5=True, session=None):
    """
    Fetch members and/or bands for each bundle in `names`. Returns {name: [paths]}.

    `names` are file ids, URLs, or paths to bundles on disk. Pass an ISSDCRequester as `session`
    to reuse one login; otherwise one is opened for the batch, unless every name is already a
    local path -- a purely local fetch needs no PRADAN credentials at all. A remote bundle
    re-authenticates per name and retries once on a dead session; transient connection drops are
    already retried underneath by the range reader itself.
    """
    if session is None and not all(Path(name).exists() for name in names):
        with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as new_session:
            return fetch(names, out_dir, include, exclude, bands, verify_md5, new_session)

    out = {}
    for name in names:
        for attempt in (1, 2):
            try:
                if not Path(name).exists():
                    session.refresh()
                zf, size = open_bundle(session, name)
                with zf:
                    members = select(zf, include, exclude)
                    targets = [Path(out_dir) / m.filename for m in members]
                    already_done = bool(members) and all(t.exists() for t in targets)
                    if already_done:
                        paths = targets
                        msg = f"{Path(name).stem}: already fetched, skipped ({size / 1e9:.2f} GB bundle)"
                    else:
                        paths = fetch_members(zf, out_dir, include, exclude)
                        got = sum(p.stat().st_size for p in paths)
                        msg = f"{Path(name).stem}: {got / 1e6:.2f} MB of {size / 1e9:.2f} GB bundle"
                        if verify_md5 and paths:
                            checked = verify(paths)
                            if checked:
                                msg += f" ({', '.join(checked)} checksum ok, rest verified by the zip itself)"
                            else:
                                msg += " (verified by the zip itself, no checksum published)"
                    if bands:
                        fout, read, full = fetch_bands(zf, out_dir, bands)
                        paths.append(fout)
                        msg += f"; {len(bands)} bands -> {fout.name} (inflated {100 * read / full:.0f}% of cube)"
                out[name] = paths
                print(msg, flush=True)
                break
            except SessionExpired:
                if attempt == 1 and not Path(name).exists():
                    print(f"{name}: session expired, refreshing and retrying", flush=True)
                    continue
                out[name] = []
                print(f"{name}: FAILED, session expired even after refresh", file=sys.stderr, flush=True)
                break
            except Exception as err:
                out[name] = []
                print(f"{name}: FAILED {type(err).__name__}: {err}", file=sys.stderr, flush=True)
                break
    return out


def main_cli():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="IIRS file ids, URLs, or local bundle zips (default: stdin)")
    parser.add_argument("-o", "--out_dir", default="./data", help="output directory (default ./data)")
    parser.add_argument("--include", default="", help="comma-separated globs to fetch (default: all)")
    parser.add_argument("--exclude", default=",".join(DEFAULT_EXCLUDE), help="comma-separated globs to skip")
    parser.add_argument("--bands", help="bands to pull from the .qub, e.g. '10,54,100-110'")
    parser.add_argument("--no-verify-md5", action="store_true", help="skip md5 checks on extracted files")
    args = parser.parse_args()

    names = args.names or [line.strip() for line in sys.stdin if line.strip()]
    if not names:
        parser.error("give one or more bundle names, or pipe them on stdin")

    def globs(s):
        return tuple(g for g in (p.strip() for p in s.split(",")) if g)

    fetch(
        names,
        args.out_dir,
        globs(args.include),
        globs(args.exclude),
        parse_bands(args.bands) if args.bands else None,
        not args.no_verify_md5,
    )


if __name__ == "__main__":
    main_cli()
