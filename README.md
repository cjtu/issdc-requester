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
# file_list.txt
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

