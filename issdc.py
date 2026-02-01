import functools
import logging
import os
import re
import sys
import threading
import time
import http
from http.client import IncompleteRead
from pathlib import Path

import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, HTTPError
from tqdm import tqdm
import argparse

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
    raise FileNotFoundError(
        "The .env file is missing. Please make a .env file with ISSDC_USERNAME and ISSDC_PASSWORD."
    )

# Constants
BASE_URL = "https://pradan.issdc.gov.in"
PAYLOAD_VISIT_URL = f"{BASE_URL}/ch2/protected/payload.xhtml"
TQDM_PARAMS = dict(unit="B", unit_scale=True, unit_divisor=1024, mininterval=1)
BLOCK_SIZE = 8192
RETRIES = 5
RETRY_SLEEP_SEC = 2
RETRY_HTTP_CODES = [
    http.HTTPStatus.TOO_MANY_REQUESTS,
    http.HTTPStatus.INTERNAL_SERVER_ERROR,
    http.HTTPStatus.BAD_GATEWAY,
    http.HTTPStatus.SERVICE_UNAVAILABLE,
    http.HTTPStatus.GATEWAY_TIMEOUT
]
LOGLVL = {3: logging.DEBUG, 2: logging.INFO, 1: logging.ERROR}

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
        "level_map": lambda x: "raw" if "nri" in x else "calibrated",
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
        "level_map": lambda x: "derived"
        if "ndn" in x
        else ("raw" if "nra" in x else "calibrated"),
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
OTHER_DOWNLOADS = 'other_downloads.txt'

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
                except HTTPError as err:  # Other exceptions are raised as usual
                    logging.error(err, exc_info=True)
                    if err.response.status_code not in retry_http_codes:
                        logging.debug(
                            f"Unexpected HTTPError {err.response.status_code}, handle or add to retry_http_codes."
                        )
                        # raise err  # TODO: raise unexpected http errors?
                except (IncompleteRead, ChunkedEncodingError, ConnectionError) as err:
                    # logging.debug(err, exc_info=True)  # Connection Broken (IncompleteRead->ProtocolError->ChunkedEncodingError)
                    logging.debug("Lost connection to server.")
                    reconnects += 1
                    if reconnects >= 2*retries:
                        logging.error(f"Connection failed after {reconnects} dropped connects.")
                        raise RuntimeError(f"Exceeded max connection retries. Please check internet connection and try again to resume your download.")
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
        payload_visit_res = self.request_session.get(
            PAYLOAD_VISIT_URL, headers=headers, allow_redirects=True
        )

        logging.debug(f"Payload visit status: {payload_visit_res.status_code}")
        # TODO: better error message for when server is down (ConnectionError, no response)

        auth_url_regex = re.compile(
            '<form.*action="(https://idp\\.issdc\\.gov\\.in/auth.*?)"'
        )
        auth_url_match = auth_url_regex.search(payload_visit_res.text)
        if auth_url_match == None:
            raise Exception("Unable to find auth URL")

        auth_url = auth_url_match.group(1).replace("&amp;", "&")
        logging.debug(f"Aquired auth URL: {auth_url}")

        # Store cookies for next request
        cookies = requests.utils.cookiejar_from_dict(
            requests.utils.dict_from_cookiejar(self.request_session.cookies)
        )

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
        logging.debug(
            f"Keep alive payload visit status: {payload_visit_res.status_code}"
        )

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


# Functions
def main(file_paths, out_dir="./data", verbose=2, logfile=".issdc.log"):
    """
    Main function to process and download files from ISSDC.
    Args:
        file_paths (str, Path, or list): Input file paths, either as a string, Path object, or list of file paths.
        out_dir (str, optional): Output directory where files will be downloaded. Defaults to ".".
        verbose (int, optional): Verbosity level for logging (0-3). Defaults to 0.
        logfile (str, optional): Log file name. Defaults to ".issdc.log".
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
    logging.info(f"Connecting to PRADAN...")
    with ISSDCRequester(username=ISSDC_USERNAME, password=ISSDC_PASSWORD) as creds:
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        logging.info(f"Success! Starting download of {len(file_paths)} file(s).")
        for file_path in file_paths:
            logging.info(f"Starting {Path(file_path).name}")
            download(creds, file_path, out_dir)

        logging.info(f"Finished downloading to {Path(out_dir).resolve()}.")


@retry_http(RETRIES, RETRY_SLEEP_SEC, RETRY_HTTP_CODES)
def _download(
    session, file_url, data_dir, total_size, byte_range_support, block_size=BLOCK_SIZE
):
    """
    Download handler with progress bar and resume logic.

    If byte_range_support, allows resuming downloads. The file's total_size in
    bytes is needed (e.g. response headers['content-length'])
    """
    file_name = Path(file_url).name.split("?")[0]
    fp = Path(data_dir) / file_name
    open_mode = "ab" if byte_range_support else "wb"
    with open(fp, open_mode) as f:
        pos = f.tell()
        logging.debug(f"Opened file: {fp} at byte {pos}.")
        if pos >= total_size:
            if total_size == 0:
                logging.info(f"File not found on server: {file_url}")
                os.remove(fp)
                return
            logging.info(f"Skipping... File already downloaded: {fp}")
            return
        headers = None
        if byte_range_support:
            headers = {"Range": f"bytes={f.tell()}-"}
        logging.debug(f"Downloading {fp} with headers: {headers}")
        with session.request("get", file_url, stream=True, headers=headers) as response:
            response.raise_for_status()  # raise bad html status as HTTPError exception
            if "tqdm" in sys.modules:
                with tqdm(
                    desc=file_name, initial=pos, total=total_size, **TQDM_PARAMS
                ) as pbar:
                    for chunk in response.iter_content(block_size):
                        f.write(chunk)
                        pbar.update(len(chunk))
            else:
                for chunk in response.iter_content(block_size):
                    f.write(chunk)
    logging.debug(f"Downloaded complete: {fp}")


def download(session, file_url, data_dir):
    """
    Download a file using a logged in ISSDCRequester session.

    Parameters
    ----------
    session: ISSDCRequester
    file_url: str
      Full url starting `https://pradan.issdc.gov` and often ending `.ext?instrument`.
      > Ex. 'https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2023/11/23/ch2_cla_l1_20231123T231214771_20231123T231220147.fits?class'
    data_dir: str
    """
    # Initial request: get file size, check byte range (resume partial download) support
    with session.request("head", file_url) as response:
        byte_range_support = response.headers.get("Accept-Ranges", "") == "bytes"
        total_size = int(response.headers.get("content-length", 0))
    return _download(session, file_url, data_dir, total_size, byte_range_support)


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
                
                # Append extension if missing (checking against common extensions to avoid double extension)
                if not any(img_url.lower().endswith(xx) for xx in [".zip", ".fits", ".tif", ".xml", ".pdf", ".txt", ".lbl", ".fmt", ".csv", ".tab"]):
                    img_url += ext

                return f"{BASE_URL}/{base}/{date_path}/{img_url}?{query}"
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
    with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session:        
        with tempfile.TemporaryDirectory() as out_dir:
            for url in TEST_FILES:
                with session.request("HEAD", url) as resp:
                    assert resp.status_code == 200, f"HEAD failed for {url}"
                    expected_size = int(resp.headers.get("content-length", 0))
                    
                download(session, url, str(out_dir))
                
                # Verify
                fname = Path(url.split("?")[0]).name
                fpath = Path(out_dir) / fname
                
                assert fpath.exists(), f"File {fpath} not found"
                assert fpath.stat().st_size == expected_size, f"Size mismatch for {fname}: expected {expected_size}, got {fpath.stat().st_size}"
        

def test_other_downloads_exist():
    """Iterate through all OTHER_DOWNLOADS files and verify the urls still exist."""
    urls = read_file_paths(OTHER_DOWNLOADS)
    stale_urls = []
    with ISSDCRequester(ISSDC_USERNAME, ISSDC_PASSWORD) as session:
        for url in urls:
            try:
                # Using HEAD to check existence without downloading
                resp = session.request("HEAD", url)
                # Some servers might return 405 Method Not Allowed for HEAD, fallback to GET with stream=True
                if resp.status_code == 405:
                    resp = session.request("GET", url, stream=True)
                    resp.close()
                
                if resp.status_code != 200:
                    stale_urls.append((url, f"Status {resp.status_code}"))
            except Exception as e:
                stale_urls.append((url, str(e)))
    print(f"Results: {len(urls) - len(stale_urls)}/{len(urls)} URLs are valid")
    if stale_urls:
        for url, reason in stale_urls:
            print(f"  - {url}")
            print(f"    Reason: {reason}")
    

def read_file_paths(file_path: str) -> list:
    """
    Reads file paths from a given text file, one per line.

    :param file_path: Path to the text file containing file paths.
    :return: List of file paths.
    """
    paths = []
    with open(file_path, "r") as f:
        for line in f:
            if line[0] in ("#", "\n"):  # Skip commented lines
                continue
            paths.append(img2url(line.strip()))
    return paths


if __name__ == "__main__":
    ## DEBUG ##
    # main(['/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2024/11/30/ch2_cla_l1_20241130T233743748_20241130T233747523.fits?class'], verbose=3)
    # quit()

    # Set up argument parser
    help_info = """Download files from ISSDC PRADAN server.

    Prerequisites: 
    1) pip or conda install requests tqdm
    2) Create file .env with 2 lines: ISSDC_USERNAME=user@email.com ISSDC_PASSWORD=password
    """
    parser = argparse.ArgumentParser(description=help_info)
    parser.add_argument(
        "file_list",
        type=str,
        nargs='?',
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
        help="Get all other downloads for this instrument from PRADAN (options: class,xsm,iirs,sar,ohrc,tmc2,chace2,dfrs,spice)."
    )
    # Parse arguments
    args = parser.parse_args()

    if args.test:
        test_short_list_download()
    elif args.od_exist:
        test_other_downloads_exist()
    elif args.instrument_od:
        files = get_other_downloads(args.instrument_od)
        if files:
            main(files, args.out_dir, args.verbose, args.logfile)
        else:
            print(f"No files matched instrument '{args.instrument_od}'.")
    else:
        # Run main function with parsed arguments
        if not args.file_list:
            parser.error("Please supply name of text file with PRADAN file paths. See --help for details.")
        
        main(args.file_list, args.out_dir, args.verbose, args.logfile)
