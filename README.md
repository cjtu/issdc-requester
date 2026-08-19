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

## Partial downloads: `issdc-iirs`

An IIRS bundle is a multi-GB zip whose bulk is one `.qub` cube. PRADAN supports byte ranges, so
`issdc-iirs` mounts the remote zip and reads only the members you ask for — no full download.

Fetch just the ancillary files (seconds, ~30 MB out of a 5.5 GB bundle):

```sh
issdc-iirs --include '*.oat,*.spm' -o ./data ch2_iir_nci_20201202T1923525130_d_img_d32
```

Globs are case-insensitive and match the internal path or the bare name (`geometry/*` works too).
`--exclude` defaults to `*.qub`; passing your own replaces that default rather than adding to it.

Fetch selected bands out of the cube:

```sh
issdc-iirs --bands 10,54,100-110 -o ./data ch2_iir_nci_20201202T1923525130_d_img_d32
```

The cube is BSQ, so a band is contiguous — but deflate has no random access inside a member, so
reaching band N means inflating and discarding everything before it. **Cost scales with the
highest band requested, not the count**: band 54 of 256 is ~21% of the stream, band 251 ~98%.

The subset is written **sparse at full size**: each band lands at its true offset and the
bundle's own ENVI header is kept, so the file opens as an ordinary 256-band IIRS cube with
unfetched bands reading as zero — `read(54)` is band 54, no band-name bookkeeping. Apparent size
is the whole cube; real disk use is only what was fetched (`du`, not `ls`). Re-running with
different bands fills in the same file.

Names may also be local zip paths, in which case the network is skipped entirely.

### Integrity

- Every member is CRC32-checked by `zipfile` as it decompresses.
- Extracted files are md5-checked against the `md5_checksum` in their PDS4 label. Only labelled
  products publish one — the cube, the geometry csv, the browse png; `miscellaneous/` files
  (`.oat`, `.spm`, `.lbr`) have no label, so the CRC is all there is. `--no-verify` skips it.
- A downloaded `.zip` is checked for completeness as soon as it lands; `issdc --deep-verify`
  CRC-checks every member too (slow on a multi-GB bundle). PRADAN publishes no checksum for the
  zip itself — no `Content-MD5`, and the ETag is only size+mtime.
- A band subset is partial by construction, so neither check applies to it.

## Metadata index: `issdc-index`

`issdc-index` uses the same ranged reads to scrape each product's PDS4 label (~75 KB out of a
multi-GB bundle) into a local, queryable `iirs_index.jsonl`. See the module docstring.

## Offline tests

```sh
issdc-iirs --selftest    # synthetic bundle, no credentials or network
issdc-index --selftest
```
