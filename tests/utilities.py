import base64
import contextlib
import datetime
from os import environ
from time import sleep

import docker
import pytest
import urllib3
from conftest import Constants as C
from Crypto.Cipher import PKCS1_v1_5 as PKCS115_Cipher
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
import socket

import nethsm as nethsm_module


@pytest.fixture(scope="module")
def nethsm():
    """Start Docker container with Nethsm image and connect to Nethsm

    This Pytest Fixture will run before the tests to provide the tests with
    a nethsm instance via Docker container, also the first provision of the
    NetHSM will be done in here"""

    container = docker_container()

    with connect(C.AdminUser) as nethsm:
        provision(nethsm)
        yield nethsm

    try:
        container.kill()
    except docker.errors.APIError:
        pass


def docker_container():
    client = docker.from_env()

    while True:
        containers = client.containers.list(
            filters={"ancestor": C.IMAGE}, ignore_removed=True
        )
        print(containers)
        if len(containers) == 0:
            break

        for container in containers:
            try:
                container.remove(force=True)
            except docker.errors.APIError as e:
                print(e)
                pass
        sleep(1)

    container = client.containers.run(
        C.IMAGE,
        "",
        name="nethsm",
        hostname="nethsm",
        ports={"8443": 8443},
        remove=True,
        detach=True,
    )

    http = urllib3.PoolManager(cert_reqs="CERT_NONE")
    print("Waiting for container to be ready")
    while True:
        try:
            response = http.request("GET", f"https://{C.HOST}/api/v1/health/alive")
            print(f"Response: {response.status}")
            if response.status == 200:
                break
        except Exception as e:
            print(e)
            pass
        sleep(0.5)

    return container


@contextlib.contextmanager
def connect(username):
    with nethsm_module.connect(
        C.HOST, C.VERSION, username.USER_ID, C.PASSWORD, C.VERIFY_TLS
    ) as nethsm_out:
        yield nethsm_out


def provision(nethsm):
    """Initial provisioning of a NetHSM.

    If unlock or admin passphrases are not set, they have to be entered
    interactively.  If the system time is not set, the current system time is
    used."""
    if nethsm.get_state().value == "Unprovisioned":
        system_time = datetime.datetime.now(datetime.timezone.utc)
        nethsm.provision("unlockunlock", "adminadmin", system_time)


def add_user(nethsm, username):
    """Create a new user on the NetHSM.

    If the real name, role or passphrase are not specified, they have to be
    specified interactively.  If the user ID is not set, it is generated by the
    NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        nethsm.get_user(user_id=username.USER_ID)
    except nethsm_module.NetHSMError:
        nethsm.add_user(
            username.REAL_NAME, username.ROLE, C.PASSPHRASE, username.USER_ID
        )


def generate_rsa_key_pair(length_in_bit):
    key_pair = RSA.generate(length_in_bit)
    length_in_byte = int(length_in_bit / 8)
    # "big" byteorder is needed, it's the dominant order in networking
    p = base64.b64encode(key_pair.p.to_bytes(length_in_byte, "big"))
    q = base64.b64encode(key_pair.q.to_bytes(length_in_byte, "big"))
    e = base64.b64encode(key_pair.e.to_bytes(length_in_byte, "big"))
    p = str(p, "utf-8").strip()
    q = str(q, "utf-8").strip()
    e = str(e, "utf-8").strip()
    return p, q, e


def verify_rsa_signature(public_key: str, message: SHA256.SHA256Hash, signature: bytes):
    key = RSA.importKey(public_key)
    return PKCS1_PSS.new(key).verify(message, signature)


def encrypt_rsa(public_key: str, message: str):
    public_key = RSA.importKey(public_key)
    cipher = PKCS115_Cipher.new(public_key)
    return cipher.encrypt(bytes(message, "utf-8"))


def lock(nethsm):
    if nethsm.get_state().value == "Operational":
        nethsm.lock()
    assert nethsm.get_state().value == "Locked"


def unlock(nethsm, unlock_passphrase):
    if nethsm.get_state().value == "Locked":
        nethsm.unlock(unlock_passphrase)
    assert nethsm.get_state().value == "Operational"


def set_backup_passphrase(nethsm):
    """Set the backup passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    """
    nethsm.set_backup_passphrase(C.BACKUP_PASSPHRASE)


def update(nethsm):
    """Load an update to a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role.

    Todo Further Optimization would download the latest.zip, unzip it and
    get the update from there"""

    try:
        with open(C.FILENAME_UPDATE_IN_TEST, "rb") as f:
            nethsm.update(f)
    except OSError as e:
        print(e, type(e))
        assert False