# Issdc-requester

`issdc-requester` is a Python script designed to download files from the ISSDC PRADAN server. It handles authentication, and retries in case the connection is interrupted.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/issdc-requester.git
    cd issdc-requester
    ```

2. Install the required packages, `requests` and `tqdm` (optional, for progress bars):
    ```sh
    pip install requests tqdm
    ```

3. Create a `.env` file with your ISSDC credentials:
    ```
    ISSDC_USERNAME=user@email.com
    ISSDC_PASSWORD=password
    ```

## Test installation and env

```sh
python issdc.py --help
python issdc.py --test
```

## Usage Example

To use the CLI, provide a text file containing the list of the urls from PRADAN to download, one per line.

```sh
python issdc.py file_list.txt -o ./data
```

Where `file_list.txt` contains files like:

```txt
https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/cla_collection/cla/data/calibrated/2019/09/13/ch2_cla_l1_20190913T065629048_20190913T065637048.fits?class
https://pradan.issdc.gov.in/ch2/protected/downloadData/POST_OD/isda_archive/ch2_bundle/cho_bundle/nop/sar_collection/data/calibrated/20200305/ch2_sar_ncls_20200305t114902885_d_cp_d18.zip?sar
```
