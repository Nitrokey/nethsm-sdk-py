import datetime
from io import BytesIO

import pytest
from conftest import Constants as C
from utilities import lock, self_sign_csr, unlock

import nethsm as nethsm_module
from nethsm import NetHSM, TlsKeyType

"""########## Preparation for the Tests ##########

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


def get_config_logging(nethsm: NetHSM) -> None:
    data = nethsm.get_config_logging()
    assert data.ip_address == C.IP_ADDRESS_LOGGING
    assert data.port == C.PORT
    assert data.log_level == C.LOG_LEVEL


def get_config_network(nethsm: NetHSM) -> None:
    data = nethsm.get_config_network()
    assert data.ip_address == C.IP_ADDRESS_NETWORK
    assert data.netmask == C.NETMASK
    assert data.gateway == C.GATEWAY


def get_config_time(nethsm: NetHSM) -> None:
    dt_nethsm = nethsm.get_config_time()
    dt_now = datetime.datetime.now(datetime.timezone.utc)

    seconds_diff = (dt_nethsm - dt_now).total_seconds()

    # Magic Constant 2.0
    # Due to network latency and execution time, the time difference may vary.
    # Therefore the time check allows a delta of nearly 2.0 seconds.

    assert abs(seconds_diff) < 2.0


"""##########Start of Tests##########"""


def test_csr(nethsm: NetHSM) -> None:
    csr = nethsm.csr(
        C.COUNTRY,
        C.STATE_OR_PROVINCE,
        C.LOCALITY,
        C.ORGANIZATION,
        C.ORGANIZATIONAL_UNIT,
        C.COMMON_NAME,
        C.EMAIL_ADDRESS,
    )
    print(csr)


def test_set_certificate(nethsm: NetHSM) -> None:

    csr = nethsm.csr(
        C.COUNTRY,
        C.STATE_OR_PROVINCE,
        C.LOCALITY,
        C.ORGANIZATION,
        C.ORGANIZATIONAL_UNIT,
        C.COMMON_NAME,
        C.EMAIL_ADDRESS,
    )
    cert = self_sign_csr(csr)
    nethsm.set_certificate(cert)

    remote_cert = nethsm.get_certificate()
    assert cert.decode("utf-8") == remote_cert


def generate_tls_key(nethsm: NetHSM) -> None:
    nethsm.generate_tls_key(TlsKeyType.RSA, 2048)


def test_get_config_logging(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For logging

    This command requires authentication as a user with the Administrator
    role."""
    get_config_logging(nethsm)


def test_get_config_network(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For network

    This command requires authentication as a user with the Administrator
    role."""
    get_config_logging(nethsm)


def test_get_config_time(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For time

    This command requires authentication as a user with the Administrator
    role."""

    get_config_time(nethsm)


def test_get_config_unattended_boot(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For unattended boot

    This command requires authentication as a user with the Administrator
    role."""
    unattended_boot = nethsm.get_config_unattended_boot()
    assert (
        unattended_boot == C.UNATTENDED_BOOT_OFF.value
        or unattended_boot == C.UNATTENDED_BOOT_ON.value
    )


def test_get_config_get_public_key(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For get public key

    This command requires authentication as a user with the Administrator
    role.
    Todo: More checks"""
    # public_key = nethsm_alt.get_public_key()
    str_begin = nethsm.get_public_key()[:26]
    assert str_begin == "-----BEGIN PUBLIC KEY-----"
    str_end = nethsm.get_public_key()[-25:-1]
    assert str_end == "-----END PUBLIC KEY-----"


def test_get_config_get_certificate(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For get certificate

    This command requires authentication as a user with the Administrator
    role.
    Todo: More checks"""
    # certificate = nethsm_alt.get_certificate()
    str_begin = nethsm.get_certificate()[:27]
    assert str_begin == "-----BEGIN CERTIFICATE-----"
    str_end = nethsm.get_certificate()[-26:-1]
    assert str_end == "-----END CERTIFICATE-----"


def test_set_backup_passphrase(nethsm: NetHSM) -> None:
    """Set the backup passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role. Todo: Later the test would try to do an update with the changed
    passphrase which asserts True and with a wrong passphrase which asserts
    true only if failing. Because this test is dependant of set_backup,
    reset and restore it would be better to write an own module for that with
    a suitable fixture"""
    nethsm.set_backup_passphrase(C.BACKUP_PASSPHRASE_CHANGED)
    nethsm.set_backup_passphrase(
        C.BACKUP_PASSPHRASE, current_passphrase=C.BACKUP_PASSPHRASE_CHANGED
    )


# @pytest.mark.skip(reason="not finished yet")
def test_set_get_logging_config(nethsm: NetHSM) -> None:
    """Set the logging configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    Todo: I don't know which parameters i should set the nethsm to
    Write test which with get_config_logging asserts that given Parameters
    were set"""
    nethsm.set_logging_config(C.IP_ADDRESS_LOGGING, C.PORT, C.LOG_LEVEL)
    get_config_logging(nethsm)


# @pytest.mark.skip(reason="not finished yet")
def test_set_get_network_config(nethsm: NetHSM) -> None:
    """Set the network configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    Todo: I don't know which parameters i should set the nethsm to
    Write test which with get_config_network asserts that given Parameters
    were set"""
    nethsm.set_network_config(C.IP_ADDRESS_NETWORK, C.NETMASK, C.GATEWAY)
    get_config_network(nethsm)


def test_set_get_time(nethsm: NetHSM) -> None:
    """Set the system time of a NetHSM.

    If the time is not given as an argument, the system time of this system
    is used.

    This command requires authentication as a user with the Administrator
    role."""
    time_now = datetime.datetime.now(datetime.timezone.utc)
    nethsm.set_time(time_now)
    get_config_time(nethsm)


def test_set_get_unattended_boot(nethsm: NetHSM) -> None:
    """Set the unattended boot configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    unattended_boot = nethsm.get_config_unattended_boot()
    if unattended_boot == C.UNATTENDED_BOOT_OFF.value:
        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_ON)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_ON.value

        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_OFF)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_OFF.value

    if unattended_boot == C.UNATTENDED_BOOT_ON.value:
        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_OFF)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_OFF.value

        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_ON)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_ON.value


def test_set_unlock_passphrase_lock_unlock(nethsm: NetHSM) -> None:
    """Set the unlock passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""

    nethsm.set_unlock_passphrase(
        C.UNLOCK_PASSPHRASE_CHANGED, current_passphrase=C.UNLOCK_PASSPHRASE
    )

    lock(nethsm)
    unlock(nethsm, C.UNLOCK_PASSPHRASE_CHANGED)

    with pytest.raises(nethsm_module.NetHSMError):
        lock(nethsm)
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG)

    with pytest.raises(nethsm_module.NetHSMError):
        lock(nethsm)
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG_CASE)
