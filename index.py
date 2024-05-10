import os
import pathlib
from dotenv import load_dotenv
from issdc import ISSDCRequester
import re
from tqdm import tqdm

load_dotenv()

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

    # Mid file (~100 MB) all good
    # '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/iir_collection/data/raw/20221219/ch2_iir_nri_20221219T0005336511_d_img_d32.zip?iirs',
    # Lil files all good
    '/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2023/11/23/ch2_cla_l1_20231123T231214771_20231123T231220147.fits?class'
  ]

  data_dir = './data'
  pathlib.Path(data_dir).mkdir(parents=True, exist_ok=True)

  block_size = 1024  # block size for downloading
  tqdm_params = dict(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)

  for file_path in file_paths:
    print('Downloading:', file_path)
    response = creds.request_path('get', file_path, stream=True)
    # NOTE: Some of this can live in the lib too - yeeeeeee les do it
    if response.status_code == 200:
      print('Download completed')
    else:
      print('File download failed, do some error handling here. Maybe hit that refresh and try again or something.')

    file_name = re.findall("filename=(.+)", response.headers['Content-Disposition'])[0].lstrip("'\"").rstrip("\"'")  # who even is reggie's ex
    size = int(response.headers.get('content-length', 0))
    with tqdm(desc=f"Downloading {file_name}", total=size, **tqdm_params) as pbar:
      fp = f'{data_dir}/{file_name}'
      with open(fp, 'wb') as f:
        for data in response.iter_content(block_size):
          f.write(data)
          pbar.update(len(data))
        print(f'File written to {fp}')
    if size != 0 and pbar.n != size:
      print(f'Download failed at block {pbar.n}, {fp}')
    print('Download complete')
