"""
Local searchable index of Chandrayaan-2 IIRS products on PRADAN.

PRADAN has no queryable catalog, and every PDS4 label lives inside a multi-GB bundle zip.
This module scrapes each label once over HTTP byte ranges (~75 KB read out of a ~9 GB zip),
stores the useful fields as one JSON object per line in ``iirs_index.jsonl``, and answers
queries locally with no PRADAN round trip.

    from issdc_index import search, get, urls

    rows = search(exposure_gain="e2g2", level_code="nci")
    rows = search(lat_range=(-90, -85))            # corner-box overlap
    rows = search(start_time=("2021-01-01", "2021-02-01"))
    issdc.main(urls(rows))

Build/refresh the index (needs PRADAN credentials, ~45 min for the full ~5100 scenes)::

    issdc-index names.json --workers 4
    issdc-index --retry-failed

One product per line, appended as it arrives and never rewritten: an interrupted run keeps
every row it already fetched, git diffs stay per-scene, and a query is a list comprehension
over plain dicts with nothing to import but the standard library.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import warnings
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from issdc import ISSDC_PASSWORD, ISSDC_USERNAME, ISSDCRequester, img2url
from tqdm import tqdm

INDEX = Path(__file__).parent / "iirs_index.jsonl"

# PRADAN serves ~90 label reads per session and then 403s it permanently; re-auth costs ~3 s.
REAUTH_EVERY = 75


def failures_path(index_path=INDEX):
    """Where a run records the scenes it could not read, for --retry-failed."""
    index_path = Path(index_path)
    return index_path.with_name(index_path.stem + "_failures.txt")


# zipfile issues many tiny reads; BufferedReader coalesces them into range GETs. Larger buffers
# overfetch and time out against PRADAN.
RANGE_BUFFER_SIZE = 64 * 1024

# Instrument properties identical across every scene indexed so far, spanning nri/nci/ndi. Kept
# out of the rows and merged back by load(), so callers see them on every row. A scene that
# disagrees keeps its own value inline and warns -- these are assumptions, not facts.
# Two traps: level_code, processing_level and data_type are constant only in an nci-only sample;
# and removing a key here drops it from every index already written, so backfill in the same
# change.
CONSTANTS = {
    "gain": "g2",
    "n_bands": 256,
    "n_samples": 250,
    "detector_pixel_width": 30.0,
    "focal_length": 74.999,
    "line_exposure_duration": 53.06,
}

_WARNED = set()  # (field, value) pairs already reported by drop_constants()

LEVELS = {"nri": "raw", "nci": "calibrated", "ndi": "derived"}
BYTES_PER_PX = {"UnsignedLSB2": 2, "SignedLSB2": 2, "IEEE754LSBSingle": 4}
CORNERS = {"ul": "upper_left", "ur": "upper_right", "ll": "lower_left", "lr": "lower_right"}

_ID = "{*}Identification_Area/{*}"
_OA = "{*}Observation_Area/{*}"
_PP = _OA + "Mission_Area/{*}Product_Parameters/{*}"
_GEO = _OA + "Mission_Area/{*}Geometry_Parameters/{*}"
_FILE = "{*}File_Area_Observational/{*}File/{*}"
_ARR = "{*}File_Area_Observational/{*}Array_3D_Spectrum/{*}"

# field name -> (element path, cast). Fields absent from raw (nri) labels stay None.
FIELDS = {
    "logical_identifier": (_ID + "logical_identifier", str),
    "processing_level": (_OA + "Primary_Result_Summary/{*}processing_level", str),
    "start_time": (_OA + "Time_Coordinates/{*}start_date_time", str),
    "stop_time": (_OA + "Time_Coordinates/{*}stop_date_time", str),
    "imaging_orbit_number": (_PP + "imaging_orbit_number", int),
    "dumping_orbit_number": (_PP + "dumping_orbit_number", int),
    "exposure": (_PP + "exposure", str),
    "gain": (_PP + "gain", str),
    "exposure_duration": (_PP + "exposure_duration", float),
    "line_exposure_duration": (_PP + "line_exposure_duration", float),
    "detector_temperature": (_PP + "detector_temperature", float),
    "tertiary_mirror_temperature": (_PP + "tertiary_mirror_temperature", float),
    "spectrometer_casing_temperature": (_PP + "spectrometer_casing_temperature", float),
    "dewar_vw_temperature": (_PP + "dewar_vw_temperature", float),
    "detector_pixel_width": (_PP + "detector_pixel_width", float),
    "focal_length": (_PP + "focal_length", float),
    "spacecraft_altitude": (_PP + "spacecraft_altitude", float),
    "pixel_resolution": (_PP + "pixel_resolution", float),
    "roll": (_PP + "roll", float),
    "pitch": (_PP + "pitch", float),
    "yaw": (_PP + "yaw", float),
    "sun_azimuth": (_PP + "sun_azimuth", float),
    "sun_elevation": (_PP + "sun_elevation", float),
    "solar_incidence": (_PP + "solar_incidence", float),
    "orbit_limb_direction": (_PP + "orbit_limb_direction", str),
    "spacecraft_yaw_direction": (_PP + "spacecraft_yaw_direction", str),
    "reference_data_used": (_PP + "reference_data_used", str),
    "projection": (_PP + "projection", str),
    "area": (_PP + "area", str),
    "data_type": (_ARR + "Element_Array/{*}data_type", str),
    "unit": (_ARR + "Element_Array/{*}unit", str),
    "qub_file_size": (_FILE + "file_size", int),
    "md5_checksum": (_FILE + "md5_checksum", str),
    "creation_date_time": (_FILE + "creation_date_time", str),
}
for _k, _name in CORNERS.items():
    FIELDS[_k + "_lat"] = (_GEO + "System_Level_Coordinates/{*}" + _name + "_latitude", float)
    FIELDS[_k + "_lon"] = (_GEO + "System_Level_Coordinates/{*}" + _name + "_longitude", float)
    FIELDS["ref_" + _k + "_lat"] = (_GEO + "Refined_Corner_Coordinates/{*}" + _name + "_latitude", float)
    FIELDS["ref_" + _k + "_lon"] = (_GEO + "Refined_Corner_Coordinates/{*}" + _name + "_longitude", float)


# ---------------------------------------------------------------- label parsing


def _text(root, path, cast):
    """Return the cast text of the first element matching path, or None."""
    el = root.find(path)
    if el is None or el.text is None or not el.text.strip():
        return None
    try:
        return cast(el.text.strip())
    except ValueError:
        return None


def _parse_time(s):
    """Parse a PDS4 timestamp. fromisoformat rejects 'Z' and 4-digit fractions before 3.11."""
    if not s:
        return None
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".")
        s = head + "." + frac[:6].ljust(6, "0")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def parse_label(xml_bytes, file_id, url=None, bundle_size=None):
    """Extract one index row from a PDS4 label. Pure function -- unit-testable offline."""
    root = ET.fromstring(xml_bytes)
    row = {"file_id": file_id, "level_code": file_id.split("_")[2]}
    for key, (path, cast) in FIELDS.items():
        row[key] = _text(root, path, cast)

    row["exposure_gain"] = (row["exposure"] or "") + (row["gain"] or "") or None
    start, stop = _parse_time(row["start_time"]), _parse_time(row["stop_time"])
    row["duration_s"] = round((stop - start).total_seconds(), 3) if start and stop else None

    axes = {a.find("{*}axis_name").text: int(a.find("{*}elements").text) for a in root.findall(_ARR + "Axis_Array")}
    row["n_bands"], row["n_lines"], row["n_samples"] = axes.get("BAND"), axes.get("LINE"), axes.get("SAMPLE")

    # ponytail: naive min/max, so a scene crossing the pole or the 0/360 meridian reports a box
    # wider than it is. Fine as a coarse prefilter; tighten with real geometry if it ever bites.
    for prefix in ("", "ref_"):
        lats = [row[prefix + k + "_lat"] for k in CORNERS if row[prefix + k + "_lat"] is not None]
        lons = [row[prefix + k + "_lon"] for k in CORNERS if row[prefix + k + "_lon"] is not None]
        row[prefix + "lat_min"], row[prefix + "lat_max"] = (min(lats), max(lats)) if lats else (None, None)
        row[prefix + "lon_min"], row[prefix + "lon_max"] = (min(lons), max(lons)) if lons else (None, None)

    row["url"] = url if url is not None else img2url(file_id)
    row["bundle_size"] = bundle_size
    row["ingested_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return row


# ---------------------------------------------------------------- store


def load(path=INDEX, _cache={}):
    """Read the index, cached by (path, mtime) so an edit on disk is picked up."""
    path = Path(path)
    if not path.exists():
        return []
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _cache:
        _cache.clear()
        with path.open() as f:
            # A row's own value always wins, so a scene that broke an assumption keeps it.
            _cache[key] = [{**CONSTANTS, **json.loads(line)} for line in f if line.strip()]
    return _cache[key]


def drop_constants(row):
    """
    Strip fields that match CONSTANTS, warning about any that do not.

    The warning is the point: it tells us an assumed-constant field varies in the wild, so the
    remaining scenes can correct a bad assumption instead of silently inheriting it.
    """
    out = {}
    for key, val in row.items():
        if key in CONSTANTS:
            if val == CONSTANTS[key]:
                continue
            # Once per broken assumption, not once per scene: a whole batch of raw products
            # would otherwise bury the run in one warning each.
            if (key, repr(val)) not in _WARNED:
                _WARNED.add((key, repr(val)))
                warnings.warn(
                    f"{key}={val!r} (first seen in {row.get('file_id')}) breaks the assumed "
                    f"constant {CONSTANTS[key]!r}; stored inline. Drop it from CONSTANTS if it "
                    f"keeps recurring.",
                    stacklevel=2,
                )
        out[key] = val
    return out


def save(rows, path=INDEX):
    """Rewrite the whole index, sorted by file_id so git diffs stay per-scene."""
    tmp = Path(path).with_suffix(".jsonl.tmp")
    with tmp.open("w") as f:
        for row in sorted(rows, key=lambda r: r["file_id"]):
            f.write(json.dumps(drop_constants(row)) + "\n")
    tmp.replace(path)


# ---------------------------------------------------------------- query


def _best_corner(row, key):
    """Best available bound: our georeferencing, else the label's refined, else system-level."""
    for prefix in ("georef_", "ref_"):
        val = row.get(prefix + key)
        if val is not None:
            return val
    return row.get(key)


def _overlaps(row, axis, lo, hi):
    """True if the row's corner box on this axis overlaps [lo, hi] at all."""
    row_max, row_min = _best_corner(row, axis + "_max"), _best_corner(row, axis + "_min")
    return row_max is not None and row_max >= lo and row_min <= hi


def _match(row, key, val):
    got = row.get(key)
    if isinstance(val, tuple) and len(val) == 2:  # 2-tuple -> inclusive range
        return got is not None and val[0] <= got <= val[1]
    if isinstance(val, (list, set, frozenset)):  # list -> membership
        return got in val
    return got == val


def search(path=INDEX, lat_range=None, lon_range=None, pred=None, **filters):
    """
    Query the index. Returns a list of row dicts.

    Scalar filter -> equality, list -> membership, 2-tuple -> inclusive range::

        search(exposure_gain="e2g2", level_code="nci")
        search(exposure=["e2", "e3"])
        search(start_time=("2021-01-01", "2021-02-01"))     # ISO strings sort correctly

    ``lat_range``/``lon_range`` are box *overlap*, not containment, and use refined corners
    where they exist. ``pred`` is the escape hatch for anything else::

        search(lat_range=(-90, -85))
        search(pred=lambda r: r["detector_temperature"] > 90 and r["sun_elevation"] < 5)
    """
    rows = load(path)
    for key, val in filters.items():
        rows = [r for r in rows if _match(r, key, val)]
    for axis, rng in (("lat", lat_range), ("lon", lon_range)):
        if rng is not None:
            rows = [r for r in rows if _overlaps(r, axis, *rng)]
    if pred is not None:
        rows = [r for r in rows if pred(r)]
    return rows


def get(file_id, path=INDEX):
    """Return the single row for a file_id, or None."""
    return next((r for r in load(path) if r["file_id"] == file_id), None)


def urls(rows):
    """Download URLs for rows (or file_ids), ready for issdc.main()."""
    return [r["url"] if isinstance(r, dict) else img2url(r) for r in rows]


def update_georef(file_id, source, path=INDEX, **corners):
    """
    Write georeferenced corners for a row, e.g.::

        update_georef("ch2_iir_nci_...", "gcp-v2", ul=(-88.1, 332.2), ur=..., ll=..., lr=...)

    These live in their own georef_* namespace that the ingest never touches, so re-ingesting a
    scene refreshes its label fields without disturbing this. search() prefers them over the
    label's ref_* corners, which in turn beat the system-level ones.
    """
    rows = load(path)
    row = next((r for r in rows if r["file_id"] == file_id), None)
    if row is None:
        raise KeyError(file_id)
    for key, (lat, lon) in corners.items():
        if key not in CORNERS:
            raise ValueError(f"unknown corner '{key}', expected one of {sorted(CORNERS)}")
        row["georef_" + key + "_lat"], row["georef_" + key + "_lon"] = lat, lon
    lats = [row.get("georef_" + k + "_lat") for k in CORNERS if row.get("georef_" + k + "_lat") is not None]
    lons = [row.get("georef_" + k + "_lon") for k in CORNERS if row.get("georef_" + k + "_lon") is not None]
    row["georef_lat_min"], row["georef_lat_max"] = (min(lats), max(lats)) if lats else (None, None)
    row["georef_lon_min"], row["georef_lon_max"] = (min(lons), max(lons)) if lons else (None, None)
    row["georef_source"] = source
    row["georef_updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save(rows, path)
    return row


# ---------------------------------------------------------------- ingest


class HTTPRangeReader(io.RawIOBase):
    """Seekable read-only file over an HTTP resource that supports byte ranges."""

    def __init__(self, session, url, size):
        self.session, self.url, self.size, self.pos = session, url, size, 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.pos = offset
        elif whence == io.SEEK_CUR:
            self.pos += offset
        elif whence == io.SEEK_END:
            self.pos = self.size + offset
        return self.pos

    def read(self, n=-1):
        end = self.size if (n is None or n < 0) else min(self.pos + n, self.size)
        if self.pos >= self.size or end <= self.pos:
            return b""
        r = self.session.request("get", self.url, headers={"Range": f"bytes={self.pos}-{end - 1}"}, timeout=120)
        r.raise_for_status()
        data = r.content
        self.pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


def read_names(source):
    """
    File ids from a names file: JSON (any nesting of lists, e.g. the scraper's {e1: [...]})
    or one name per line. '.zip' and '?iirs' suffixes are stripped.
    """
    text = Path(source).read_text()
    try:
        data = json.loads(text)
        names = []
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, str):
                names.append(item)
    except json.JSONDecodeError:
        names = text.splitlines()
    out = []
    for name in names:
        name = name.strip().split("?")[0]
        if name.endswith(".zip"):
            name = name[:-4]
        if name:
            out.append(name)
    return sorted(set(out))


def fetch_row(session, file_id):
    """Read one product's label through a ranged zip read and return its index row."""
    url = img2url(file_id)
    with session.request("head", url) as head:
        head.raise_for_status()
        bundle_size = int(head.headers["content-length"])
        if head.headers.get("Accept-Ranges") != "bytes":
            raise OSError("server does not support byte ranges")
    reader = io.BufferedReader(HTTPRangeReader(session, url, bundle_size), buffer_size=RANGE_BUFFER_SIZE)
    with zipfile.ZipFile(reader) as zf:
        labels = [m for m in zf.infolist() if m.filename.lower().endswith(".xml") and "/data/" in "/" + m.filename]
        if not labels:
            raise OSError("no data/*.xml label in bundle")
        xml_bytes = zf.read(labels[0])
    return parse_label(xml_bytes, file_id, url=url, bundle_size=bundle_size)


def build_index(names, path=INDEX, workers=4, limit=None, reauth_every=REAUTH_EVERY):
    """
    Scrape labels for `names` and stream them into the index, one JSON line per product.

    Each row is appended the moment it arrives and is never revisited, so an interrupted run
    keeps everything it had fetched and re-running resumes from there. Names already in the
    index are skipped; delete their lines to re-fetch them.

    A scene that fails is recorded and skipped rather than aborting the run, retried once at
    the end, and any still failing are listed in <index>_failures.txt for --retry-failed.
    """
    path = Path(path)
    indexed = {row["file_id"] for row in load(path)}
    todo = [name for name in names if name not in indexed]
    if limit:
        todo = todo[:limit]
    print(f"{len(names)} names, {len(indexed)} already indexed, {len(todo)} to fetch")
    if not todo:
        return 0

    failures = {}
    written = 0
    with (
        ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session,
        path.open("a") as out,
        ThreadPoolExecutor(workers) as pool,
        tqdm(total=len(todo), unit="scene") as bar,
    ):

        def fetch_batch(batch):
            nonlocal written
            session.refresh()
            jobs = {pool.submit(fetch_row, session, name): name for name in batch}
            for job in as_completed(jobs):
                name = jobs[job]
                bar.update(1)
                try:
                    row = job.result()
                except Exception as err:
                    failures[name] = f"{type(err).__name__}: {err}"
                    tqdm.write(f"FAILED {name}: {failures[name][:160]}", file=sys.stderr)
                    continue
                failures.pop(name, None)
                out.write(json.dumps(drop_constants(row)) + "\n")
                out.flush()
                written += 1

        # Batched so the session is re-authenticated before PRADAN cuts it off.
        for start in range(0, len(todo), reauth_every):
            fetch_batch(todo[start : start + reauth_every])

        retry = sorted(failures)
        if retry:
            tqdm.write(f"retrying {len(retry)} failures", file=sys.stderr)
            bar.reset(total=len(retry))
            for start in range(0, len(retry), reauth_every):
                fetch_batch(retry[start : start + reauth_every])

    fail_file = failures_path(path)
    fail_file.write_text("".join(name + "\n" for name in sorted(failures)))
    for name, err in sorted(failures.items()):
        print(f"FAILED {name}: {err}", file=sys.stderr)
    print(f"{written} rows written to {path}, {len(failures)} failures -> {fail_file}")
    return written


# ---------------------------------------------------------------- tests


def ids_of(rows):
    return sorted(row["file_id"] for row in rows)


def test_parse_label():
    """Parse the sample labels in tests/ if present (they are not shipped -- too large)."""
    samples = sorted((Path(__file__).parent / "tests").glob("*.xml"))
    if not samples:
        print("test_parse_label: SKIP (no tests/*.xml)")
        return
    for sample in samples:
        row = parse_label(sample.read_bytes(), sample.stem, url="x://y")
        assert row["exposure_gain"] == row["exposure"] + row["gain"], row["file_id"]
        assert row["n_bands"] == 256, row
        assert row["lat_min"] <= row["lat_max"]
        # Cube size from the axes must reproduce the label's own file_size: catches a swapped
        # LINE/SAMPLE or a miscounted band, which nothing else in the row would reveal.
        est = row["n_bands"] * row["n_lines"] * row["n_samples"] * BYTES_PER_PX[row["data_type"]]
        assert abs(est - row["qub_file_size"]) < row["n_bands"] * row["n_samples"] * 4, row["file_id"]
        assert row["level_code"] in LEVELS
        assert row["duration_s"] > 0
        print(f"test_parse_label: {sample.stem} {row['exposure_gain']} {row['duration_s']}s OK")


def test_search():
    """Search semantics and corner precedence, against a throwaway index."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.jsonl"
        rows = [
            {
                "file_id": "a",
                "exposure_gain": "e1g2",
                "level_code": "nci",
                "start_time": "2020-12-02T00:00:00",
                "lat_min": -89.0,
                "lat_max": -80.0,
                "ref_lat_min": None,
                "ref_lat_max": None,
                "sun_elevation": 2.0,
            },
            {
                "file_id": "b",
                "exposure_gain": "e2g2",
                "level_code": "nci",
                "start_time": "2021-01-15T00:00:00",
                "lat_min": -70.0,
                "lat_max": 10.0,
                "ref_lat_min": None,
                "ref_lat_max": None,
                "sun_elevation": 40.0,
            },
            {
                "file_id": "c",
                "exposure_gain": "e3g2",
                "level_code": "nri",
                "start_time": "2021-06-01T00:00:00",
                "lat_min": 10.0,
                "lat_max": 40.0,
                "ref_lat_min": 50.0,  # label's own refined corners disagree with system-level
                "ref_lat_max": 60.0,
                "sun_elevation": 60.0,
            },
        ]
        save(rows, path)
        ids = ids_of
        assert ids(search(path, exposure_gain="e1g2")) == ["a"]
        assert ids(search(path, exposure_gain=["e1g2", "e3g2"])) == ["a", "c"]
        assert ids(search(path, level_code="nci")) == ["a", "b"]
        assert ids(search(path, start_time=("2021-01-01", "2021-02-01"))) == ["b"]
        assert ids(search(path, lat_range=(-90, -85))) == ["a"], "overlap, not containment"
        assert ids(search(path, lat_range=(-90, 90))) == ["a", "b", "c"]
        assert ids(search(path, lat_range=(70, 80))) == []
        assert ids(search(path, pred=lambda r: r["sun_elevation"] < 5)) == ["a"]
        assert ids(search(path, level_code="nci", lat_range=(-90, -85))) == ["a"]
        assert get("b", path)["exposure_gain"] == "e2g2"
        assert get("zzz", path) is None

        # Corner precedence: georef_* (ours) > ref_* (label's refined) > system-level.
        assert ids(search(path, lat_range=(52, 58))) == ["c"], "label ref_* beats system-level"
        assert ids(search(path, lat_range=(15, 20))) == [], "system-level ignored once ref_* exists"
        update_georef("c", "gcp-v2", path=path, ul=(-89.5, 0.0), lr=(-88.0, 10.0))
        assert ids(search(path, lat_range=(-90, -89.2))) == ["c"], "georef_* must win"
        assert ids(search(path, lat_range=(52, 58))) == [], "georef_* supersedes label ref_*"
        assert get("c", path)["georef_source"] == "gcp-v2"
        assert get("c", path)["ref_lat_min"] == 50.0, "ingest-owned ref_* left untouched"
        print("test_search: OK")


def test_constants():
    """Hoisted constants round-trip invisibly, and a scene that breaks one warns and keeps it."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.jsonl"
        normal = {"file_id": "a", "lat_min": 1.0, "lat_max": 2.0, **CONSTANTS}
        odd = {"file_id": "b", "lat_min": 1.0, "lat_max": 2.0, **CONSTANTS, "gain": "g1"}
        _WARNED.clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            save([normal, odd], path)
        assert len(caught) == 1, [str(w.message) for w in caught]
        assert "gain" in str(caught[0].message)

        # Constant fields must not be in the file, but must come back out of it.
        raw = [json.loads(line) for line in path.open()]
        assert "gain" not in raw[0] and "n_bands" not in raw[0], raw[0]
        assert raw[1]["gain"] == "g1", "a value that broke the assumption stays inline"
        assert get("a", path) == normal, "round-trip must be lossless"
        assert get("b", path)["gain"] == "g1", "row value beats the constant"
        assert get("b", path)["n_bands"] == 256, "other constants still merge in"
        assert ids_of(search(path, gain="g2")) == ["a"], "constants are queryable"
        assert ids_of(search(path, n_bands=256)) == ["a", "b"]
        print("test_constants: OK")


def main_cli():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="?", help="JSON or line-delimited file of IIRS basenames")
    parser.add_argument("-o", "--out", default=INDEX, help=f"index path (default {INDEX})")
    parser.add_argument("-w", "--workers", type=int, default=4, help="concurrent fetches (default 4)")
    parser.add_argument("-n", "--limit", type=int, help="only fetch the first N missing scenes")
    parser.add_argument("--retry-failed", action="store_true", help="re-fetch the names a previous run failed on")
    parser.add_argument("--selftest", action="store_true", help="run offline tests and exit")
    args = parser.parse_args()

    if args.selftest:
        test_search()
        test_constants()
        test_parse_label()
        return
    source = failures_path(args.out) if args.retry_failed else args.names
    if not source:
        parser.error("give a names file or --retry-failed")
    build_index(read_names(source), args.out, args.workers, args.limit)


if __name__ == "__main__":
    main_cli()
