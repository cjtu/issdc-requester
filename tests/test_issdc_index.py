"""
Offline self-checks for issdc_index.py: search/query semantics, hoisted-constant round-trip,
and PDS4 label parsing against the sample labels in this directory. No credentials or network
needed.

Run directly: python tests/test_issdc_index.py
"""

import json
import sys
import tempfile
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from issdc_index import _WARNED, BYTES_PER_PX, CONSTANTS, LEVELS, get, parse_label, save, search, update_georef


def ids_of(rows):
    return sorted(row["file_id"] for row in rows)


def test_parse_label():
    """Parse the sample labels in this directory, if present (they are not shipped -- too large)."""
    samples = sorted(Path(__file__).parent.glob("*.xml"))
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


if __name__ == "__main__":
    test_search()
    test_constants()
    test_parse_label()
    print("all issdc_index checks passed")
