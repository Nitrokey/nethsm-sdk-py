# nethsm-sdk-py

Python client for NetHSM. NetHSM documentation available here: [NetHSM documentation](https://docs.nitrokey.com/nethsm/)

[![codecov.io][codecov-badge]][codecov-url]

[codecov-badge]: https://codecov.io/gh/nitrokey/nethsm-sdk-py/branch/main/graph/badge.svg
[codecov-url]: https://app.codecov.io/gh/nitrokey/nethsm-sdk-py/tree/main

## Usage

Installation:

```sh
pip install nethsm
```

Example program:

```py
import nethsm

host="nethsmdemo.nitrokey.com"
version="v1"
username="admin"
password="Administrator"
verify_tls=False

with nethsm.connect(
        host, version, username, password, verify_tls
    ) as nethsm_instance:
  print(nethsm_instance.list_keys())

```

## Development

### Setting Up The Environment

Use `make init` to set up the development environment.

You can then run `make check` to run the checks on your changes and `make fix` to format the code.

### Updating the client

To update the NetHSM HTTP client, you need to download the updated ``nethsm-api.yml`` OpenAPI specification. The easiest is to download it from the NetHSM demo server (``curl`` required):

```sh
make nethsm-api.yaml --always-make
```

Then, run the generation script, docker is required:

```sh
make nethsm-client
```  

Be sure to run the linter, tests and check that everything is working as expected after the update.

### Custom functions

The generator doesn't support upload of binary files and custom `Content-Type` headers (fails to serialize).
To work around this, some functions are written manually, using `NetHSM.request()` to send the request.

The current list of such functions is:

- `NetHSM.set_key_certificate()` : `/keys/{KeyID}/cert`
- `NetHSM.set_certificate()` : `/config/tls/cert.pem`
- `NetHSM.update()`: `/system/update`, manual deserialization because the content-type header is sent twice, see [#245 on the NetHSM repo](https://git.nitrokey.com/nitrokey/nethsm/nethsm/-/issues/245)

### Publishing a new version

- change the version in `nethsm/VERSION`. Example : 0.1.0
- create a new tag, prepending `v` to the version. Example : v0.1.0
- create a new release on GitHub to trigger the ci that will publish the new version.
