import argparse
import functools
import http
import io
import logging
import os
import re
import sys
import threading
import time
import zipfile
from http.client import IncompleteRead
from pathlib import Path

import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, HTTPError
from tqdm import tqdm

# Load ISSDC_USERNAME and ISSDC_PASSWORD from the file ".env" with contents:
#  ISSDC_USERNAME=user@email.com
#  ISSDC_PASSWORD=password
env_path = Path(".env")
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            if line.startswith("ISSDC_USERNAME"):
                ISSDC_USERNAME = line.strip().split("=")[1]
            elif line.startswith("ISSDC_PASSWORD"):
                ISSDC_PASSWORD = line.strip().split("=")[1]
else:
    # Not fatal at import: img2url and the offline index need no credentials. ISSDCRequester
    # raises when something actually tries to authenticate.
    ISSDC_USERNAME = ISSDC_PASSWORD = None

# Constants
BASE_URL = "https://pradan.issdc.gov.in"
PAYLOAD_VISIT_URL = f"{BASE_URL}/ch2/protected/payload.xhtml"
IDP_HOST = "idp.issdc.gov.in"  # a request redirected here means the session died, not a real 404
# mininterval=1 live-updates a real terminal; redirected to a file (nohup, a log), tqdm's `\r`
# updates never overwrite and every one becomes its own line, so back off to one line per 30 s.
TQDM_PARAMS = dict(unit="B", unit_scale=True, unit_divisor=1024, mininterval=1 if sys.stderr.isatty() else 30)
BLOCK_SIZE = 8192
# zipfile issues many tiny reads; a BufferedReader coalesces them into range GETs.
RANGE_BUFFER_SIZE = 64 * 1024
RETRIES = 5
RETRY_SLEEP_SEC = 2
RETRY_HTTP_CODES = [
    http.HTTPStatus.TOO_MANY_REQUESTS,
    http.HTTPStatus.INTERNAL_SERVER_ERROR,
    http.HTTPStatus.BAD_GATEWAY,
    http.HTTPStatus.SERVICE_UNAVAILABLE,
    http.HTTPStatus.GATEWAY_TIMEOUT,
]
LOGLVL = {3: logging.DEBUG, 2: logging.INFO, 1: logging.ERROR}

# IIRS level code (3rd underscore-separated field of the file name) -> PRADAN data directory.
CH2_IIR_LEVELS = {"nri": "raw", "nci": "calibrated", "ndi": "derived"}


def ch2_iir_level(img_url):
    """Return the PRADAN data directory for an IIRS file name, by its level code."""
    code = img_url.split("_")[2]
    if code not in CH2_IIR_LEVELS:
        raise ValueError(f"Unknown IIRS level code '{code}', expected one of {sorted(CH2_IIR_LEVELS)}")
    return CH2_IIR_LEVELS[code]


# Instrument path config for inferring full PRADAN paths from file names.
INSTRUMENT_CONFIG = {
    "ch2_cla": {
        "base_path": "ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated",
        "query": "class",
        "date_idx": 3,
        "date_fmt_path": "%Y/%m/%d",
        "ext": ".fits",
    },
    "ch2_iir": {
        "base_path": "ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/{level}",
        "query": "iirs",
        "date_idx": 3,
        "date_fmt_path": "%Y%m%d",
        "level_map": ch2_iir_level,
        "ext": ".zip",
    },
    "ch2_sar": {
        "base_path": "ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/sar_collection/data/{level}",
        "query": "sar",
        "date_idx": 3,
        "date_fmt_path": "%Y%m%d",
        "level_map": lambda x: "raw" if x.split("_")[2].startswith("nr") else "calibrated",
        "ext": ".zip",
    },
    "ch2_tmc": {
        "base_path": "ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/tmc_collection/data/{level}",
        "query": "tmc2",
        "date_idx": 3,
        "date_fmt_path": "%Y%m%d",
        "level_map": lambda x: "derived" if "ndn" in x else ("raw" if "nra" in x else "calibrated"),
        "ext": ".zip",
    },
    "ch2_ohr": {
        "base_path": "ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/ohr_collection/data/{level}",
        "query": "ohrc",
        "date_idx": 3,
        "date_fmt_path": "%Y%m%d",
        "level_map": lambda x: "raw" if "nrp" in x else "calibrated",
        "ext": ".zip",
    },
}

# Testing
TEST_FILES = [
    # SPICE Kernel (.ti text file, small)
    "https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/spice/spice_kernels/ik/ch2_iir_v01.ti?spice",
    # TXT (TMC procedure, small)
    "https://pradan.issdc.gov.in/ch2/protected/downloadFile/tmc2/LTA_Assembly_Procedure.txt",
    # CLASS .fits (L1 file)
    "https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2019/09/13/ch2_cla_l1_20190913T065629048_20190913T065637048.fits?class",
]
OTHER_DOWNLOADS = Path(__file__).parent / "resources" / "other_downloads.txt"

# Instrument mapping for Other Downloads
OD_INSTRUMENT_MAP = {
    "class": "class_holder/",
    "xsm": "xsm/",
    "iirs": "iirs/",
    "sar": "sar/",
    "ohrc": "ohrc/",
    "tmc2": "tmc2/",
    "chace2": "chace2/",
    "dfrs": "dfrs/",
    "spice": "spice/",
}


# Decorators
def retry_http(retries, retry_sleep_sec, retry_http_codes):
    """
    Decorator that retries wrapped function after a sleep on http errors.

    Does all error handling. Make sure response.raise_for_status() is called to
    raise HTMLError exceptions. Statuses in retry_http_codes will be
    retried, all others will raise.

    Mostly from https://stackoverflow.com/a/72316062 and https://stackoverflow.com/a/61463451

    Parameters
    ----------
    retries : int
      Number of retries
    retry_sleep_sec : float
      Wait time (s) before next retry
    retry_html_codes : list
      HTML response codes that will trigger a retry
    """

    def decorator(func):
        """decorator"""

        @functools.wraps(func)  # preserve original func name
        def wrapper(*args, **kwargs):
            """wrapper"""
            attempt = 0
            reconnects = 0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except SessionExpired:
                    # A dead session won't fix itself by retrying; let main()'s refresh-and-retry handle it.
                    raise
                except HTTPError as err:  # Other exceptions are raised as usual
                    logging.error(err, exc_info=True)
                    if err.response.status_code not in retry_http_codes:
                        logging.debug(
                            f"Unexpected HTTPError {err.response.status_code}, handle or add to retry_http_codes."
                        )
                        # raise err  # TODO: raise unexpected http errors?
                except (IncompleteRead, ChunkedEncodingError, ConnectionError):
                    # logging.debug(err, exc_info=True)  # Connection Broken (IncompleteRead->ProtocolError->ChunkedEncodingError)
                    logging.debug("Lost connection to server.")
                    reconnects += 1
                    if reconnects >= 2 * retries:
                        logging.exception(f"Connection failed after {reconnects} dropped connects.")
                        raise RuntimeError(
                            "Exceeded max connection retries. Please check internet connection and try again to resume your download."
                        )
                except Exception as err:
                    logging.error(err, exc_info=True)
                attempt += 1
                logging.debug(f"Retrying... (attempt {attempt} / {retries}).")
                time.sleep(retry_sleep_sec)
            logging.error("func %s retry failed", func)
            raise RuntimeError(f"Exceeded max retries: {retries} failed")

        return wrapper

    return decorator


# Classes
class SessionExpired(Exception):
    """Raised when a request indicates a dead session without throwing a normal HTTPError."""


class ISSDCRequester:
    """
    ISSDCRequester handles authentication and requests to the ISSDC server.

    Attributes:
      username (str): The username for ISSDC authentication.
      password (str): The password for ISSDC authentication.
      request_session (requests.Session): The session object to manage requests.
      keep_alive_interval (int): The interval in seconds for keep-alive requests.
      interval_thread (SetInterval): The thread object for keep-alive requests.
    Methods:
      __auth(): Complete the authentication flow on the ISSDC site and return cookies.
      __keep_alive(): Send a keep-alive request to the ISSDC server.
      refresh(): Refresh ISSDC authorization and start the keep-alive thread.
      request(method, url, **kwargs): Perform a request with the given method and URL.
      close(): Close the current session and clear authentication data.
    """

    def __init__(self, username, password, keep_alive_interval=600):
        """
        Initializes the ISSDC requester with the given credentials and settings.
        Args:
          username (str): The username for authentication.
          password (str): The password for authentication.
          keep_alive_interval (int, optional): The interval in seconds to keep the session alive. Defaults to 600.
        """
        if not username or not password:
            raise FileNotFoundError(
                "Missing ISSDC credentials. Please make a .env file with ISSDC_USERNAME and ISSDC_PASSWORD."
            )
        self.username = username
        self.password = password
        self.request_session = None
        self.keep_alive_interval = keep_alive_interval
        self.interval_thread = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False  # Don't suppress exceptions

    @retry_http(RETRIES, RETRY_SLEEP_SEC, RETRY_HTTP_CODES)
    def __auth(self):
        """
        INTERNAL METHOD
        Complete the auth flow on the issdc site. Return a dictionary-like object of cookies.
        An exception will be raised if the authorization fails.
        """
        # Close any current session on new auth
        self.close()

        # Create a session to carry headers/cookies across requests
        # This session should also handle keep alive pings
        self.request_session = requests.session()

        headers = {"User-Agent": "Mozilla/5.0"}
        payload_visit_res = self.request_session.get(PAYLOAD_VISIT_URL, headers=headers, allow_redirects=True)

        logging.debug(f"Payload visit status: {payload_visit_res.status_code}")
        # TODO: better error message for when server is down (ConnectionError, no response)

        auth_url_regex = re.compile('<form.*action="(https://idp\\.issdc\\.gov\\.in/auth.*?)"')
        auth_url_match = auth_url_regex.search(payload_visit_res.text)
        if auth_url_match == None:
            raise Exception("Unable to find auth URL")

        auth_url = auth_url_match.group(1).replace("&amp;", "&")
        logging.debug(f"Aquired auth URL: {auth_url}")

        # Store cookies for next request
        cookies = requests.utils.cookiejar_from_dict(requests.utils.dict_from_cookiejar(self.request_session.cookies))

        # Refusing the redirect is important here
        # When redirected the server expects your cookie to be set on your non-existent client
        auth_res = self.request_session.post(
            auth_url,
            headers=headers,
            data={"username": self.username, "password": self.password},
            cookies=cookies,
            allow_redirects=False,
        )

        if auth_res.status_code == 302:
            return auth_res.cookies
        else:
            logging.debug(f"Login failed with status: {auth_res.status_code}")
            raise Exception(f"Failed to login with status: {auth_res.status_code}")

    def __keep_alive(self):
        """
        Send the "keep alive" request to the issdc server.
        """
        payload_visit_res = self.request_session.get(PAYLOAD_VISIT_URL)
        logging.debug(f"Keep alive payload visit status: {payload_visit_res.status_code}")

    def refresh(self):
        """
        Refresh issdc authorization.
        If threading, this should not be called during an ongoing request as the original auth tokens will be invalidated and the request will fail.
        """
        self.cookies = self.__auth()

        # Spawn a thread with a keep-alive signal.
        # This keep-alive extends the life of the authorization and is not the same as the automatic keep-alive provided by the session.
        self.interval_thread = SetInterval(self.__keep_alive, self.keep_alive_interval)

    def request(self, method, url, **kwargs):
        """
        Perform a request.
        This function wraps the 'requests' library signature and injects cookies required for authorization.
        If there is no active session, one will be created.
        """
        # NOTE: If session was already defined check for an unauthorized response on initial request and trigger an automatic refresh/retry
        if self.request_session == None:
            self.refresh()
        return self.request_session.request(method, url, cookies=self.cookies, **kwargs)

    def close(self):
        """
        Close the current session and clear auth data.
        """
        if self.request_session != None:
            self.request_session.close()
            self.request_session = None
        if self.interval_thread != None:
            self.interval_thread.stop()
            self.interval_thread = None
        self.cookies = None


class SetInterval:
    """
    Repeatedly execute function at given interval on a background thread.

    Attributes:
      function (callable): The function to execute.
      interval (float): The time interval (in seconds).
      stop_event (threading.Event): An event to signal the thread to stop execution.
    """

    def __init__(self, function, interval):
        """
        Initializes the SetInterval instance and starts the interval execution.
        Args:
          function (callable): The function to be executed at each interval.
          interval (float): The time interval (in seconds) between each function execution.
        """
        self.function = function
        self.interval = interval
        self.stop_event = threading.Event()
        thread = threading.Thread(target=self.__setInterval)
        thread.daemon = True  # Will die when the main thread dies
        thread.start()

    def __setInterval(self):
        """Runs function at each interval."""
        next = time.time() + self.interval
        while not self.stop_event.wait(next - time.time()):
            next += self.interval
            self.function()

    def stop(self):
        """Stop execution."""
        self.stop_event.set()


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

    @retry_http(RETRIES, RETRY_SLEEP_SEC, RETRY_HTTP_CODES)
    def read(self, n=-1):
        end = self.size if (n is None or n < 0) else min(self.pos + n, self.size)
        if self.pos >= self.size or end <= self.pos:
            return b""
        r = self.session.request("get", self.url, headers={"Range": f"bytes={self.pos}-{end - 1}"}, timeout=120)
        if r.status_code == 403 or IDP_HOST in r.url:
            raise SessionExpired(self.url)
        r.raise_for_status()
        data = r.content
        self.pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


# Functions
def open_remote(session, name, buffer_size=RANGE_BUFFER_SIZE):
    """
    Open a zip on PRADAN as a lazy, seekable ZipFile. Returns (ZipFile, size in bytes).

    Only the zip's central directory is transferred here; each member is its own deflate
    stream, so reading one member costs only that member. Each range read retries transient
    connection drops and raises SessionExpired on a dead session, the same as download().

    Parameters
    ----------
    session: ISSDCRequester
    name: str
      File name, partial path or full URL, anything img2url() accepts.
    """
    url = img2url(name)
    with session.request("head", url) as head:
        if head.status_code == 403 or IDP_HOST in head.url:
            raise SessionExpired(url)
        if head.status_code != 200:
            raise OSError(f"not on server (HTTP {head.status_code}): {url}")
        size = int(head.headers["content-length"])
        if head.headers.get("Accept-Ranges") != "bytes":
            raise OSError(f"server does not support byte ranges: {url}")
    return zipfile.ZipFile(io.BufferedReader(HTTPRangeReader(session, url, size), buffer_size)), size


def main(file_paths, out_dir="./data", verbose=2, logfile=".issdc.log", verify_zip=False):
    """
    Main function to process and download files from ISSDC.
    Args:
        file_paths (str, Path, or list): Input file paths, either as a string, Path object, or list of file paths.
        out_dir (str, optional): Output directory where files will be downloaded. Defaults to ".".
        verbose (int, optional): Verbosity level for logging (0-3). Defaults to 0.
        logfile (str, optional): Log file name. Defaults to ".issdc.log".
        verify_zip (bool, optional): CRC-check every member of downloaded zips. Slow.
    Returns:
        None
    """
    logging.basicConfig(
        level=LOGLVL.get(verbose, logging.NOTSET),
        filename=logfile,
        filemode="a",
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Parse and format input file paths from file or list
    if isinstance(file_paths, (str, Path)):
        file_paths = read_file_paths(file_paths)
    elif isinstance(file_paths, list):
        file_paths = [img2url(img) for img in file_paths]

    # Authenticate
    logging.info("Connecting to PRADAN...")
    with ISSDCRequester(username=ISSDC_USERNAME, password=ISSDC_PASSWORD) as creds:
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        logging.info(f"Success! Starting download of {len(file_paths)} file(s).")
        for file_path in file_paths:
            logging.info(f"Starting {Path(file_path).name}")
            try:
                download(creds, file_path, out_dir, verify_zip=verify_zip)
            except SessionExpired:
                logging.warning(f"Session expired on {Path(file_path).name}; refreshing and retrying.")
                creds.refresh()
                download(creds, file_path, out_dir, verify_zip=verify_zip)

        logging.info(f"Finished downloading to {Path(out_dir).resolve()}.")


@retry_http(RETRIES, RETRY_SLEEP_SEC, RETRY_HTTP_CODES)
def _download(session, file_url, data_dir, total_size, byte_range_support, block_size=BLOCK_SIZE):
    """
    Download handler with progress bar and resume logic.

    If byte_range_support, allows resuming downloads. The file's total_size in
    bytes is needed (e.g. response headers['content-length'])
    """
    file_name = Path(file_url).name.split("?")[0]
    fp = Path(data_dir) / file_name
    if total_size == 0:
        # Dead session HEAD responses look like 404 (content-length: 0).
        # Clean up if file was downloaded as a stub, then stop.
        logging.info(f"File not found on server: {file_url}")
        if fp.exists() and fp.stat().st_size == 0:
            os.remove(fp)
        return
    open_mode = "ab" if byte_range_support else "wb"
    with open(fp, open_mode) as f:
        pos = f.tell()
        logging.debug(f"Opened file: {fp} at byte {pos}.")
        if pos >= total_size:
            logging.info(f"Skipping... File already downloaded: {fp}")
            return
        headers = None
        if byte_range_support:
            headers = {"Range": f"bytes={f.tell()}-"}
        logging.debug(f"Downloading {fp} with headers: {headers}")
        with session.request("get", file_url, stream=True, headers=headers) as response:
            if response.status_code == 403 or IDP_HOST in response.url:
                raise SessionExpired(file_url)
            response.raise_for_status()  # raise bad html status as HTTPError exception
            if "tqdm" in sys.modules:
                with tqdm(desc=file_name, initial=pos, total=total_size, **TQDM_PARAMS) as pbar:
                    for chunk in response.iter_content(block_size):
                        f.write(chunk)
                        pbar.update(len(chunk))
            else:
                for chunk in response.iter_content(block_size):
                    f.write(chunk)
    logging.debug(f"Downloaded complete: {fp}")


def download(session, file_url, data_dir, verify_zip=False):
    """
    Download a file using a logged in ISSDCRequester session.

    Parameters
    ----------
    session: ISSDCRequester
    file_url: str
      Full url starting `https://pradan.issdc.gov` and often ending `.ext?instrument`.
      > Ex. 'https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2023/11/23/ch2_cla_l1_20231123T231214771_20231123T231220147.fits?class'
    data_dir: str
    verify_zip: bool
      CRC-check every member of a downloaded zip, on top of the completeness check. Slow.
    """
    # Initial request: get file size, check byte range (resume partial download) support
    with session.request("head", file_url) as response:
        logging.debug(
            f"HEAD {file_url} -> status={response.status_code} url={response.url} "
            f"content-length={response.headers.get('content-length')} "
            f"accept-ranges={response.headers.get('Accept-Ranges')}"
        )
        if response.status_code == 403 or IDP_HOST in response.url:
            raise SessionExpired(file_url)
        byte_range_support = response.headers.get("Accept-Ranges", "") == "bytes"
        total_size = int(response.headers.get("content-length", 0))
    _download(session, file_url, data_dir, total_size, byte_range_support)

    fp = Path(data_dir) / Path(file_url).name.split("?")[0]
    if fp.suffix != ".zip" or not fp.exists():
        return
    try:
        with zipfile.ZipFile(fp) as zf:
            if verify_zip:
                bad = zf.testzip()
            else:
                bad = None
    except zipfile.BadZipFile as err:
        bad = str(err) or "unreadable archive"

    if bad:
        logging.error(f"CORRUPT {fp}: {bad}. Delete it and re-run to redownload.")
        print(f"CORRUPT {fp.name}: {bad}. Delete it and re-run to redownload.", file=sys.stderr)
    else:
        logging.debug(f"Verified archive: {fp}")


def other_download_url(img_url: str) -> str:
    """
    Handle URLs for 'Other Downloads' category (downloadFile endpoint).
    Detects paths that belong to the downloadFile endpoint using strict markers.

    Args:
        img_url (str): The URL or path to check.

    Returns:
        str or None: The formatted URL if detected, else None.
    """
    path = img_url.lstrip("/")

    # explicitly identified as downloadFile
    if "downloadFile" in path:
        if path.startswith("http"):
            return path
        return f"{BASE_URL}/{path}"

    # check for common_ prefixes which are usually under downloadFile
    if path.startswith("common_"):
        return f"{BASE_URL}/ch2/protected/downloadFile/{path}"

    return None


def get_other_downloads(instrument: str) -> list:
    """
    Get all files for a specific instrument and common files from the other_downloads.txt list.
    """
    if not Path(OTHER_DOWNLOADS).exists():
        print(f"Error: {OTHER_DOWNLOADS} not found.")
        return []

    # Map to search string
    search_str = OD_INSTRUMENT_MAP.get(instrument.lower(), instrument)

    # Include all files that match the instrument or are common files
    return [f for f in read_file_paths(OTHER_DOWNLOADS) if search_str in f or "common_" in f]


def img2url(img_name: str) -> str:
    """
    Convert image name to full ISSDC download URL.

    Parameters
    ----------
    img_name : str
      Image name, e.g. 'ch2_iir_nci_20210613T1540537788_d_img_hw1'
    """
    img_url = img_name.strip().lstrip("/")

    # 1. Check if it's already a full URL
    if img_url.startswith("http"):
        return img_url

    # 2. Check for Other Download patterns
    other_url = other_download_url(img_url)
    if other_url:
        return other_url

    # 3. Check for explicit ch2 paths (generic fallback for partial paths)
    if img_url.startswith("ch2/"):
        return f"{BASE_URL}/{img_url}"

    # 4. Instrument Config Parsing
    for prefix, config in INSTRUMENT_CONFIG.items():
        if img_url.startswith(prefix):
            try:
                parts = img_url.split("?")[0].split("_")

                # Resolve Level
                level = "calibrated"
                if "level_map" in config:
                    level = config["level_map"](img_url)

                base = config["base_path"].format(level=level)

                # Resolve Date
                date_str = parts[config["date_idx"]]
                # Assuming date_str is like '20190913T...' or just '20190913'
                date_val = date_str[:8]

                if config["date_fmt_path"] == "%Y/%m/%d":
                    date_path = f"{date_val[:4]}/{date_val[4:6]}/{date_val[6:8]}"
                else:
                    date_path = date_val

                query = config["query"]
                ext = config.get("ext", "")

                # Drop any query the caller already supplied, else it is duplicated below
                file_name = img_url.split("?")[0]

                # Append extension if missing (checking against common extensions to avoid double extension)
                if not any(
                    file_name.lower().endswith(xx)
                    for xx in [".zip", ".fits", ".tif", ".xml", ".pdf", ".txt", ".lbl", ".fmt", ".csv", ".tab"]
                ):
                    file_name += ext

                return f"{BASE_URL}/{base}/{date_path}/{file_name}?{query}"
            except (IndexError, ValueError) as e:
                logging.debug(f"Failed to parse {img_url} with config {prefix}: {e}")
                # Continue to next check or fail
                pass

    # 5. Ambiguous or Unrecognized
    # Fall back to requiring full URLs for ambiguous cases (XSM, CHACE, DFRS, SPICE)
    raise ValueError(f"Ambiguous or unrecognized file path '{img_name}'. Please provide the full URL.")


def test_short_list_download():
    """Download a short list of known files and verify sizes."""
    import tempfile

    with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session, tempfile.TemporaryDirectory() as out_dir:
        for url in TEST_FILES:
            with session.request("HEAD", url) as resp:
                assert resp.status_code == 200, f"HEAD failed for {url}"
                expected_size = int(resp.headers.get("content-length", 0))

            download(session, url, str(out_dir))

            # Verify
            fname = Path(url.split("?")[0]).name
            fpath = Path(out_dir) / fname

            assert fpath.exists(), f"File {fpath} not found"
            assert fpath.stat().st_size == expected_size, (
                f"Size mismatch for {fname}: expected {expected_size}, got {fpath.stat().st_size}"
            )


def _check_file_exists(session, file_url: str, out_dir: str = None) -> tuple[bool, int]:
    """
    Check if a file exists on server and if it needs downloading.

    Args:
        session: ISSDCRequester session.
        file_url: Full URL to check.
        out_dir: Local directory to check for existing files.

    Returns:
        Tuple of (exists_on_server, needs_download).
        needs_download is the remote size if download needed, 0 if already local, -1 if not on server.
    """
    resp = session.request("HEAD", file_url)
    if resp.status_code == 405:
        resp = session.request("GET", file_url, stream=True)
        resp.close()

    if resp.status_code != 200:
        return False, -1

    remote_size = int(resp.headers.get("content-length", 0))

    if out_dir:
        file_name = Path(file_url).name.split("?")[0]
        local_path = Path(out_dir) / file_name
        if local_path.exists() and local_path.stat().st_size >= remote_size:
            return True, 0

    return True, remote_size


def check_files_exist(file_paths, out_dir: str = "./data", verbose: int = 2, logfile: str = ".issdc.log") -> None:
    """
    Check if files exist on the ISSDC server without downloading.

    Args:
        file_paths: Input file paths (str, Path, or list).
        out_dir: Local directory to check for existing files.
        verbose: Verbosity level for logging (0-3).
        logfile: Log file name.
    """
    logging.basicConfig(
        level=LOGLVL.get(verbose, logging.NOTSET),
        filename=logfile,
        filemode="a",
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if isinstance(file_paths, (str, Path)):
        file_paths = read_file_paths(file_paths)
    elif isinstance(file_paths, list):
        file_paths = [img2url(img) for img in file_paths]

    found = 0
    missing_files = []
    to_download_count = 0
    total_download_size = 0

    with ISSDCRequester(username=ISSDC_USERNAME, password=ISSDC_PASSWORD) as session:
        for file_url in file_paths:
            exists, needs = _check_file_exists(session, file_url, out_dir)
            if exists:
                found += 1
                if needs > 0:
                    to_download_count += 1
                    total_download_size += needs
            else:
                file_name = Path(file_url).name.split("?")[0]
                missing_files.append(file_name)

    print(f"Found: {found}/{len(file_paths)} files on server")

    if missing_files:
        print("Not found on server:")
        for fname in missing_files:
            print(f"  {fname}")

    size_gb = total_download_size / (1024**3)
    print(f"To download: {to_download_count} files (Size: {size_gb:.3f} GB)")


def test_other_downloads_exist():
    """Iterate through all OTHER_DOWNLOADS files and verify the urls still exist."""
    urls = read_file_paths(OTHER_DOWNLOADS)
    found = 0

    with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session:
        for url in urls:
            exists, _ = _check_file_exists(session, url)
            if exists:
                found += 1

    print(f"Found: {found}/{len(urls)} URLs valid")


def read_file_paths(file_path: str) -> list:
    """
    Reads file paths from a given text file, one per line.

    :param file_path: Path to the text file containing file paths.
    :return: List of file paths.
    """
    paths = []
    with open(file_path) as f:
        for line in f:
            if line[0] in ("#", "\n"):  # Skip commented lines
                continue
            paths.append(img2url(line.strip()))
    return paths


def main_cli():
    # Set up argument parser
    help_info = """Download files from ISSDC PRADAN server.

    Ensure this directory has a file called .env with 2 lines (PRADAN login): 
    ISSDC_USERNAME=user@email.com 
    ISSDC_PASSWORD=password
    """
    parser = argparse.ArgumentParser(description=help_info)
    parser.add_argument(
        "file_list",
        type=str,
        nargs="?",
        help="Text file with PRADAN file paths, one per line. Paths may begin with https://pradan.issdc/ch2/... or /ch2/...",
    )
    parser.add_argument(
        "-o",
        "--out_dir",
        type=str,
        default="./data",
        help="Output directory for downloads.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        type=int,
        choices=[0, 1, 2, 3],
        default=2,
        help="Verbosity level for logging (0-3).",
    )
    parser.add_argument(
        "-l",
        "--logfile",
        type=str,
        default=".issdc.log",
        help="Log file name (default: .issdc.log).",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test ISSDC downloaded is working correctly.",
    )
    parser.add_argument(
        "--od-exist",
        action="store_true",
        help="Check if other_downloads.txt URLs are still valid.",
    )
    parser.add_argument(
        "-i",
        "--instrument-od",
        type=str,
        help="Get all other downloads for this instrument from PRADAN (options: class,xsm,iirs,sar,ohrc,tmc2,chace2,dfrs,spice).",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Check if files exist on the server without downloading."
    )
    parser.add_argument(
        "--verify-zip",
        action="store_true",
        help="CRC-check every member of each downloaded zip (slow; a completeness check always runs).",
    )
    # Parse arguments
    args = parser.parse_args()

    if args.test:
        test_short_list_download()
    elif args.od_exist:
        test_other_downloads_exist()
    # Other Downloads by instrument
    elif args.instrument_od:
        files = get_other_downloads(args.instrument_od)
        if not files:
            print(f"No files matched instrument '{args.instrument_od}'.")
        if args.dry_run:
            check_files_exist(files, args.out_dir, args.verbose, args.logfile)
        else:
            main(files, args.out_dir, args.verbose, args.logfile, args.verify_zip)
    # Main data downloader
    else:
        if not args.file_list:
            parser.error("Please supply name of text file with PRADAN file paths. See --help for details.")
        if args.dry_run:
            check_files_exist(args.file_list, args.out_dir, args.verbose, args.logfile)
        else:
            main(args.file_list, args.out_dir, args.verbose, args.logfile, args.verify_zip)


if __name__ == "__main__":
    main_cli()
