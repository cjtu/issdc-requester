# Issdc-requester

`issdc-requester` is a Python script designed to download files from the ISSDC PRADAN server. It handles authentication, and retries in case the connection is interrupted.

Note: this software comes with no warranties and must not be used maliciously. Users must adhere to the terms and conditions of the ISRO ISSDC and PRADAN website. 

## Installation

Install directly from GitHub:

```sh
pip install git+https://github.com/cjtu/issdc-requester.git
```

Create a `.env` file with your ISSDC credentials:

```
ISSDC_USERNAME=user@email.com
ISSDC_PASSWORD=password
```

## Test installation and env

```sh
issdc --help
issdc --test
```

## Usage Example

To use the CLI, provide a text file containing the list of the urls from PRADAN to download, one per line:

```txt
# file_list.txt (full urls or just image IDs are both acceptable)
https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/xsm_collection/auto/2025/ch2_xsm_20250308_v1.zip?xsm
https://pradan.issdc.gov.in/ch2/protected/downloadFile/common_pds4structure/isda_mission_bundle.zip
ch2_sar_ncls_20200305t114902885_d_cp_d18
ch2_tmc_nra_20191015T1021251544_d_img_d18
```

Use `--dry-run` to check that all files are found on the server and how much disk space is needed

```sh
issdc --dry-run file_list.txt -o ./my_data
```

Remove `--dry-run` to confirm and begin downloading. 

```sh
issdc file_list.txt -o ./my_data
```

If the download is interrupted, run the same command to resume where it left off.

## Partial downloads (IIRS only): `issdc-iirs`

An IIRS bundle is a multi-GB zip. Use `issdc-iirs` to read only requested parts of the bundle.

Fetch just the ancillary files (~30 MB out of a 5.5 GB bundle):

```sh
issdc-iirs --include '*.oat,*.spm' -o ./data ch2_iir_nci_20201202T1923525130_d_img_d32
```

The include patterns are case-insensitive and can match extensions or part of the IIRS file path  (e.g. `--include 'geometry/*'` works too). The `--exclude` defaults to `*.qub` (if you want the full image cube, use the plain `issdc` command above).

Fetch a subset of the bands from the cube:

```sh
issdc-iirs --bands 10,54,100-110 -o ./data ch2_iir_nci_20201202T1923525130_d_img_d32
```

**Note:** Due to how the data is organized and zipped, speed depends on the highest band requested, NOT the total number of bands (e.g. requesting just band 200 will take as long as requesting all bands 1-200).

The subset is written as a **compact cube**: only the requested bands, packed in the order given. The ENVI header will have `band names` and `wavelength` corresponding to each band

Names may also be the path to a local zip file (e.g. downloaded with `issdc`), in which case nothing is downloaded. Helpful for unpacking a subset of IIRS bands without unzipping the full cube.


## Tests

Test installation and `.env` setup:

```sh
issdc --test
```

Offline tests (for devs):

```sh
python tests/test_issdc_iirs.py
python tests/test_issdc_index.py
python tests/test_stub_guard.py
```

End to end test (dev only):

```sh
python tests/test_e2e_download.py
``` 

```sh
python tests/test_e2e_download.py
```
