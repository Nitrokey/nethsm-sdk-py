import datetime
from io import BytesIO

import pytest
from conftest import Constants as C
from utilities import nethsm, self_sign_csr  # noqa: F401
from utilities import lock, unlock

import nethsm as nethsm_module

"""########## Preparation for the Tests ##########

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


def get_config_logging(nethsm):
    data = nethsm.get_config_logging()
    assert data.ipAddress == C.IP_ADDRESS_LOGGING
    assert data.port == C.PORT
    assert str(data.logLevel) == C.LOG_LEVEL


def get_config_network(nethsm):
    data = nethsm.get_config_network()
    assert data.ipAddress == C.IP_ADDRESS_NETWORK
    assert data.netmask == C.NETMASK
    assert data.gateway == C.GATEWAY


def get_config_time(nethsm):
    time_nethsm_str = nethsm.get_config_time()
    # parse time_nethsm_str to datetime.datetime
    # 2023-09-22T14:46:12Z
    time_nethsm = datetime.datetime.strptime(time_nethsm_str, "%Y-%m-%dT%H:%M:%SZ")

    time_now = datetime.datetime.now(datetime.timezone.utc)

    assert datetime.datetime(
        time_nethsm.year,
        time_nethsm.month,
        time_nethsm.day,
        time_nethsm.hour,
        time_nethsm.minute,
    ) == datetime.datetime(
        time_now.year, time_now.month, time_now.day, time_now.hour, time_now.minute
    )


"""##########Start of Tests##########"""


def test_csr(nethsm):
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


def test_set_certificate(nethsm: nethsm_module.NetHSM) -> None:

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
    nethsm.set_certificate(BytesIO(cert))
    
    remote_cert = nethsm.get_certificate()
    assert cert.decode('utf-8') == remote_cert


def generate_tls_key(nethsm):
    resp = nethsm.generate_tls_key("RSA", 2048)
    print(resp)


def test_get_config_logging(nethsm):
    """Query the configuration of a NetHSM.

    For logging

    This command requires authentication as a user with the Administrator
    role."""
    get_config_logging(nethsm)


def test_get_config_network(nethsm):
    """Query the configuration of a NetHSM.

    For network

    This command requires authentication as a user with the Administrator
    role."""
    get_config_logging(nethsm)


def test_get_config_time(nethsm):
    """Query the configuration of a NetHSM.

    For time

    This command requires authentication as a user with the Administrator
    role."""

    get_config_time(nethsm)


def test_get_config_unattended_boot(nethsm):
    """Query the configuration of a NetHSM.

    For unattended boot

    This command requires authentication as a user with the Administrator
    role."""
    unattended_boot = nethsm.get_config_unattended_boot()
    assert (
        str(unattended_boot) == C.UNATTENDED_BOOT_OFF
        or str(unattended_boot) == C.UNATTENDED_BOOT_ON
    )


def test_get_config_get_public_key(nethsm):
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


def test_get_config_get_certificate(nethsm):
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


def test_set_backup_passphrase(nethsm):
    """Set the backup passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role. Todo: Later the test would try to do an update with the changed
    passphrase which asserts True and with a wrong passphrase which asserts
    true only if failing. Because this test is dependant of set_backup,
    reset and restore it would be better to write an own module for that with
    a suitable fixture"""
    nethsm.set_backup_passphrase(C.BACKUP_PASSPHRASE)


# @pytest.mark.skip(reason="not finished yet")
def test_set_get_logging_config(nethsm):
    """Set the logging configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    Todo: I don't know which parameters i should set the nethsm to
    Write test which with get_config_logging asserts that given Parameters
    were set"""
    nethsm.set_logging_config(C.IP_ADDRESS_LOGGING, C.PORT, C.LOG_LEVEL)
    get_config_logging(nethsm)


# @pytest.mark.skip(reason="not finished yet")
def test_set_get_network_config(nethsm):
    """Set the network configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    Todo: I don't know which parameters i should set the nethsm to
    Write test which with get_config_network asserts that given Parameters
    were set"""
    nethsm.set_network_config(C.IP_ADDRESS_NETWORK, C.NETMASK, C.GATEWAY)
    get_config_network(nethsm)


def test_set_get_time(nethsm):
    """Set the system time of a NetHSM.

    If the time is not given as an argument, the system time of this system
    is used.

    This command requires authentication as a user with the Administrator
    role."""
    time_now = datetime.datetime.now(datetime.timezone.utc)
    nethsm.set_time(time_now)
    get_config_time(nethsm)


def test_set_get_unattended_boot(nethsm):
    """Set the unattended boot configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    unattended_boot = nethsm.get_config_unattended_boot()
    if str(unattended_boot) == C.UNATTENDED_BOOT_OFF:
        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_ON)
        assert str(nethsm.get_config_unattended_boot()) == C.UNATTENDED_BOOT_ON

        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_OFF)
        assert str(nethsm.get_config_unattended_boot()) == C.UNATTENDED_BOOT_OFF

    if str(unattended_boot) == C.UNATTENDED_BOOT_ON:
        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_OFF)
        assert str(nethsm.get_config_unattended_boot()) == C.UNATTENDED_BOOT_OFF

        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_ON)
        assert str(nethsm.get_config_unattended_boot()) == C.UNATTENDED_BOOT_ON


def test_set_unlock_passphrase_lock_unlock(nethsm):
    """Set the unlock passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    nethsm.set_unlock_passphrase(C.UNLOCK_PASSPHRASE_CHANGED)

    lock(nethsm)
    unlock(nethsm, C.UNLOCK_PASSPHRASE_CHANGED)

    with pytest.raises(nethsm_module.NetHSMError):
        lock(nethsm)
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG)

    with pytest.raises(nethsm_module.NetHSMError):
        lock(nethsm)
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG_CASE)
