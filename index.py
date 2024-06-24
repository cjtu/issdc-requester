import os
import sys
import pathlib
import time
import logging
import functools
from http import HTTPStatus
from http.client import IncompleteRead
from requests.exceptions import HTTPError, ChunkedEncodingError
from dotenv import load_dotenv
from issdc import ISSDCRequester, BASE_URL
from tqdm import tqdm

load_dotenv()
TQDM_PARAMS = dict(unit='B', unit_scale=True, unit_divisor=1024, mininterval=1)
BLOCK_SIZE = 8192
RETRIES = 5
RETRY_SLEEP_SEC = 2
RETRY_HTTP_CODES = [
    HTTPStatus.TOO_MANY_REQUESTS,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.GATEWAY_TIMEOUT,
]

# TODO: make it a method of ISSDC?
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
        # preserve information about the original function, or the func name will be "wrapper" not "func"
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            """wrapper"""
            attempt = 0
            while attempt < retries:
              try:
                  return func(*args, **kwargs)
              except HTTPError as err:  # Other exceptions are raised as usual
                  logging.error(err, exc_info=True)
                  if err.response.status_code not in retry_http_codes:
                      logging.error(f"Unexpected HTTPError {err.response.status_code}, handle or add to retry_http_codes.")
                      # raise err  # TODO: raise unexpected http errors?
              except (IncompleteRead, ChunkedEncodingError) as err:
                  # logging.debug(err, exc_info=True)  # Connection Broken (IncompleteRead->ProtocolError->ChunkedEncodingError)
                  logging.error('Lost connection to server.')
                  attempt -= 1
              except Exception as err:
                  logging.error(err, exc_info=True)
                  # raise err
              attempt += 1
              logging.error(f"Retrying... (attempt {attempt+1} / {retries}).")
              time.sleep(retry_sleep_sec)
            logging.error("func %s retry failed", func)
            raise RuntimeError(f'Exceeded max retries: {retries} failed')
        return wrapper
    return decorator


@retry_http(RETRIES, RETRY_SLEEP_SEC, RETRY_HTTP_CODES)
def _download(session, file_url, data_dir, total_size, byte_range_support, block_size=BLOCK_SIZE):
  """
  Download handler with progress bar and resume logic.
  
  If byte_range_support, allows resuming downloads. The file's total_size in 
  bytes is needed (e.g. response headers['content-length'])
  """
  file_name = os.path.basename(file_url).split('?')[0]
  fp = f'{data_dir}/{file_name}'
  open_mode = 'ab' if byte_range_support else 'wb'
  with open(fp, open_mode) as f:
    pos = f.tell()
    logging.debug(f'Opened file: {fp} at byte {pos}.')
    if pos >= total_size:
      if total_size == 0:
        logging.error(f'File not found on server: {fp}')
        os.remove(fp)
      logging.info(f'Skipping... File already downloaded: {fp}')
      return
    headers = None
    if byte_range_support:
       headers = {'Range': f'bytes={f.tell()}-'}
    logging.info(f'Downloading {fp} with headers: {headers}')
    with session.request('get', file_url, stream=True, headers=headers) as response:
      response.raise_for_status()  # raise bad html status as HTTPError exception
      with tqdm(desc=file_name, initial=pos, total=total_size, **TQDM_PARAMS) as pbar:
        for chunk in response.iter_content(block_size):
          f.write(chunk)
          pbar.update(len(chunk))
  logging.info(f'Downloaded complete: {fp}')


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
  with session.request('head', file_url) as response:
    byte_range_support = response.headers.get('Accept-Ranges', '') == 'bytes'
    total_size = int(response.headers.get('content-length', 0))
  return _download(session, file_url, data_dir, total_size, byte_range_support)


def read_file_paths(file_path: str, instrument: str='iirs') -> list:
    """
    Reads file paths from a given text file, one per line.
    
    :param file_path: Path to the text file containing file paths.
    :return: List of file paths.
    """
    paths = []
    with open(file_path, 'r') as f:
        for line in f:
          if line[0] in ('#', '\n'):
              continue
          line = line.strip()
          if line.startswith('https://pradan.issdc.gov.in'):
              line = line.replace('https://pradan.issdc.gov.in', '')
          elif line.startswith('/ch2/protected/'):
              pass # already in correct format
          elif line.startswith('ch2_'): # generate full path from img name
            if instrument == 'iirs':
              date = line.split('_')[3][:8]
              line = f'/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/calibrated/{date}/{line}.zip?iirs'
            else:
                logging.error(f'Instrument {instrument} not supported, please supply full path starting with "/ch2/protected/".')
          else:
            logging.error(f'Unsupported file path format: {line}')
          paths.append(line)
    return paths


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG, filename='issdc.log', filemode='a', format="%(asctime)s [%(levelname)s] %(message)s",)

  # Parse file paths from first cmd line arg
  if len(sys.argv) > 1:
     file_paths = read_file_paths(sys.argv[1])
     logging.info(f'Got {len(file_paths)} file paths from {sys.argv[1]}.')  
  else:
    file_paths = [
      # Lil files all good
      '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2023/11/23/ch2_cla_l1_20231123T231214771_20231123T231220147.fits?class',
    
      # Mid file (25-100 MB) all good
      # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/xsm_collection/auto/2024/ch2_xsm_20240428_v1.zip?xsm',
      ]
  
  logging.info(f'Starting ISSDC download script...')
  ISSDC_USERNAME = os.getenv('ISSDC_USERNAME')
  ISSDC_PASSWORD = os.getenv('ISSDC_PASSWORD')

  # NOTE: If you just want to type your password in for testing, make sure you use a raw string so you don't need to escape it
  creds = ISSDCRequester(username=ISSDC_USERNAME, password=ISSDC_PASSWORD)


  data_dir = './data'
  pathlib.Path(data_dir).mkdir(parents=True, exist_ok=True)

  for file_path in file_paths:
    file_url = f'{BASE_URL}{file_path}'
    download(creds, file_url, data_dir)
  logging.info(f'Finished downloading to {data_dir}.')
