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

## Usage Example

To use the CLI, provide a text file containing the list of the urls from PRADAN to download, one per line.

```sh
python issdc.py --help
python issdc.py file_list.txt -o ./data
```
