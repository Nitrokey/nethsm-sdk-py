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

admin_passphrase = "adminadmin"
unlock_passphrase = "unlockunlock"

with nethsm.connect(
    host="nethsmdemo.nitrokey.com",
    auth=nethsm.Authentication(username="admin", password=admin_passphrase),
) as client:
    if client.get_state() == nethsm.State.UNPROVISIONED:
        client.provision(
            unlock_passphrase=unlock_passphrase,
            admin_passphrase=admin_passphrase,
        )

    if client.get_state() == nethsm.State.LOCKED:
        client.unlock(unlock_passphrase)

    assert client.get_state() == nethsm.State.OPERATIONAL

    client.generate_key(
        type=nethsm.KeyType.RSA,
        length=2048,
        mechanisms=[
            nethsm.KeyMechanism.RSA_SIGNATURE_PKCS1,
            nethsm.KeyMechanism.RSA_DECRYPTION_PKCS1,
            nethsm.KeyMechanism.RSA_SIGNATURE_PSS_SHA256,
            nethsm.KeyMechanism.RSA_DECRYPTION_OAEP_SHA256, 
        ],
    )

    print(client.list_keys())
```

## Compatibility

The following table provides an overview of the SDK versions that added support for new NetHSM features:

| SDK Version | NetHSM Version | New Features |
| :---------: | :------------: | ------------ |
| [v1.0.0][sdk-v1.0.0] | [v1.0][nethsm-v1.0] |  |
| [v1.2.0][sdk-v1.2.0] | [v2.0][nethsm-v2.0] | Namespaces |

[nethsm-v1.0]: https://github.com/Nitrokey/nethsm/releases/tag/v1.0
[nethsm-v2.0]: https://github.com/Nitrokey/nethsm/releases/tag/v2.0
[sdk-v1.0.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.0.0
[sdk-v1.2.0]: https://github.com/Nitrokey/nethsm-sdk-py/releases/tag/v1.2.0

New features are added in a backwards-compatible way if possible.
Trying to use them on older NetHSM versions may result in unexpected error messages.

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
To work around this, some functions are written manually, using `NetHSM._request()` to send the request.

The current list of such functions is:

- `NetHSM.set_certificate()` : `/config/tls/cert.pem`

Also, the generator cannot deserialize responses with a header that is specified in the OpenAPI document.
Therefore, the following functions manually deserialize the API response:

- `NetHSM.add_key()`: `/keys`
- `NetHSM.generate_key()`: `/keys/generate`
- `NetHSM.add_user()`: `/users`

### Publishing a new version

- change `__version__` in `nethsm/__init__.py`. Example : 0.1.0
- create a new tag, prepending `v` to the version. Example : v0.1.0
- create a new release on GitHub to trigger the ci that will publish the new version.

### Adding new tests

Testing is done via `pytest`. A test is loaded when the name of the file starts with `test_` and the function doing the test is prefixed by `test`.

Pytest fixtures are used, to get a provisioned and initialized NetHSM object to interact with, use `nethsm` as a parameter of your test function. For an unprovisioned NetHSM use `nethsm_no_provision`.

If you want to force a reset (clearing the data) of the NetHSM instance, use `start_nethsm()`, it will kill and restart the process.

If you want to get debug logs when running the tests, run `pytest -s`.

When a test is currently broken and expected to fail, decorate the test function with:

```python
@pytest.mark.xfail(reason="reason")
```

You can mark a test to be skipped:

```python
@pytest.mark.skip(reason="reason")
```

#### Test modes

By default these tests assume that a docker daemon is running and that open ports on containers can be accessed via `127.0.0.1`, meaning it will not work if run in a container.

If you want to run these tests in a container, use the `docker.io/nitrokey/nethsm:testing` image and set the environment variable `TEST_MODE=ci`. Example:

```sh
docker run -v "$PWD:/nethsm" -e FLIT_ROOT_INSTALL=1 -e TEST_MODE=ci -it --entrypoint /bin/sh nitrokey/nethsm:testing -c "apk add make python3 && cd /nethsm && make init && make test"
```

> Be aware this command will create files owned by root in your working directory.

This CI mode manually start and stops the necessary processes to run a NetHSM instance, due to its design it may break when the container image is updated.
