import os
import pathlib
from dotenv import load_dotenv
from issdc import ISSDCRequester, BASE_URL
from tqdm import tqdm

load_dotenv()
TQDM_PARAMS = dict(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
BLOCK_SIZE = 8192

# TODO: make it a method of ISSDC?
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
  print(f'Downloaded complete: {fp}.')

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
