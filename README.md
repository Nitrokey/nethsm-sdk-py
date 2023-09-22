# nethsm-sdk-py

Python client for NetHSM

## Setting Up The Environment

Use `make init` to set up the development environment.

You can then run `make check` to run the checks on your changes and `make fix` to format the code.

## Updating the client

To update the NetHSM HTTP client, you need to download the updated ``nethsm-api.yml`` OpenAPI specification. The easiest is to download it from the NetHSM demo server (``curl`` required):

```sh
make nethsm-api.yaml --always-make
```

Then, run the generation script, docker is required:

```sh
make nethsm-client
```  

Be sure to run the linter, tests and check that everything is working as expected after the update.

## Custom functions

The generator doesn't support upload of binary files and custom ``Content-Type`` headers (fails to serialize).
To work around this, some functions are written manually, using ``NetHSM.request()`` to send the request.

The current list of such functions is:

- ``NetHSM.restore()`` : ``/system/restore``
- ``NetHSM.set_key_certificate()`` : ``/keys/{KeyID}/cert``
- ``NetHSM.set_certificate()`` : ``/config/tls/cert.pem``
- ``NetHSM.update()`` : ``/system/update``
