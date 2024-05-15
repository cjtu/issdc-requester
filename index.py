import os
import pathlib
import time
import logging
import traceback
import functools
from http import HTTPStatus
from requests.exceptions import HTTPError
from dotenv import load_dotenv
from issdc import ISSDCRequester, BASE_URL
from tqdm import tqdm

load_dotenv()
TQDM_PARAMS = dict(unit='B', unit_scale=True, unit_divisor=1024, mininterval=1)
BLOCK_SIZE = 8192
RETRIES = 3
RETRY_SLEEP_SEC = 3
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
    Decorator that retries wrapped function num times after sleep seconds if
    any of the exceptions supplied are raised.
    
    Mostly from https://stackoverflow.com/a/72316062 and https://stackoverflow.com/a/61463451
    
    Parameters
    ----------
    retries : int
      Number of retries
    retry_sleep : float
      Wait time in seconds before next retry
    exceptions : list
      Exceptions that will trigger a retry
    """
    def decorator(func):
        """decorator"""
        # preserve information about the original function, or the func name will be "wrapper" not "func"
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            """wrapper"""
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except HTTPError as err:  # Other exceptions are raised as usual
                    logging.error(err)
                    logging.error(traceback.format_exc())
                    if err.response.status_code not in retry_http_codes:
                        raise err
                    time.sleep(retry_sleep_sec)
                logging.error("Trying attempt %s of %s.", attempt + 1, retries)
            logging.error("func %s retry failed", func)
            raise Exception('Exceed max retry num: {} failed'.format(retries))
        return wrapper
    return decorator


@retry_http(RETRIES, RETRY_SLEEP_SEC, RETRY_HTTP_CODES)
def download(session, file_url, data_dir, block_size=BLOCK_SIZE):
  """
  Download a file using a logged in ISSDCRequester session. 

  Parameters
  ----------
  session: ISSDCRequester
  file_url: str
    Full url starting `https://pradan.issdc.gov` and often ending `.ext?instrument`.
    > Ex. 'https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2023/11/23/ch2_cla_l1_20231123T231214771_20231123T231220147.fits?class'
  data_dir: str
  block_size: int
    Size of chunks to request
  """
  file_name = os.path.basename(file_url).split('?')[0]
  fp = f'{data_dir}/{file_name}'
  with open(fp, 'wb') as f:
    with session.request('get', file_url, stream=True) as response:
      response.raise_for_status()
      total = int(response.headers.get('content-length', 0))

      with tqdm(desc=file_name, total=total, **TQDM_PARAMS) as pbar:
        for chunk in response.iter_content(block_size):
          f.write(chunk)
          pbar.update(len(chunk))
  print(f'Downloaded complete: {fp}')

if __name__ == "__main__":
  ISSDC_USERNAME = os.getenv('ISSDC_USERNAME')
  ISSDC_PASSWORD = os.getenv('ISSDC_PASSWORD')

  # NOTE: If you just want to type your password in for testing, make sure you use a raw string so you don't need to escape it
  creds = ISSDCRequester(username=ISSDC_USERNAME, password=ISSDC_PASSWORD)

  file_paths = [
    # Big files... probably needs some work
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/calibrated/20240209/ch2_iir_nci_20240209T0809549481_d_img_d18.zip?iirs',
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/calibrated/20240210/ch2_iir_nci_20240210T1037346083_d_img_d18.zip?iirs',
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/calibrated/20240207/ch2_iir_nci_20240207T0130596160_d_img_d18.zip?iirs',
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/calibrated/20240202/ch2_iir_nci_20240202T0230093217_d_img_d18.zip?iirs',

    # Mid file (25-100 MB) all good
    '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/xsm_collection/auto/2024/ch2_xsm_20240428_v1.zip?xsm',
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/raw/20221219/ch2_iir_nri_20221219T0005336511_d_img_d32.zip?iirs',
    
    # Lil files all good
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2023/11/23/ch2_cla_l1_20231123T231214771_20231123T231220147.fits?class'
  ]

  data_dir = './data'
  pathlib.Path(data_dir).mkdir(parents=True, exist_ok=True)

  for file_path in file_paths:
    file_url = f'{BASE_URL}{file_path}'
    download(creds, file_url, data_dir)
