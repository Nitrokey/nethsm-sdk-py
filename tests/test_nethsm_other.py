from typing import Iterator

import pytest
from conftest import Constants as C
from utilities import Container, add_user, connect, lock, provision, unlock

import nethsm as nethsm_sdk
from nethsm import NetHSM

"""######################### Preparation for the Tests #########################

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


@pytest.fixture(scope="module")
def nethsm_no_provision(container: Container) -> Iterator[NetHSM]:
    """Start Docker container with Nethsm image and connect to Nethsm

    This Pytest Fixture will run before the tests to provide the tests with
    a nethsm instance via Docker container"""

    with connect(C.ADMIN_USER) as nethsm:
        yield nethsm


@pytest.fixture(scope="module")
def nethsm_no_provision_no_auth(container: Container) -> Iterator[NetHSM]:
    """Start Docker container with Nethsm image and connect to Nethsm

    This Pytest Fixture will run before the tests to provide the tests with
    a nethsm instance via Docker container"""

    with nethsm_sdk.connect(C.HOST, verify_tls=C.VERIFY_TLS) as nethsm:
        yield nethsm


"""######################### Start of Tests #########################"""


def test_state_no_auth(nethsm_no_provision_no_auth: NetHSM) -> None:
    """Query the state of a NetHSM without authentication."""
    state = nethsm_no_provision_no_auth.get_state().value
    assert state in C.STATES


def test_state(nethsm_no_provision: NetHSM) -> None:
    """Query the state of a NetHSM."""
    state = nethsm_no_provision.get_state().value
    assert state in C.STATES


def test_state_provision(nethsm_no_provision: NetHSM) -> None:
    """Initial provisioning of a NetHSM.

    If unlock or admin passphrases are not set, they have to be entered
    interactively.  If the system time is not set, the current system time is
    used."""
    provision(nethsm_no_provision)
    assert nethsm_no_provision.get_state().value == "Operational"


def test_info(nethsm_no_provision: NetHSM) -> None:
    """Query the vendor and product information for a NetHSM."""
    info = nethsm_no_provision.get_info()
    assert nethsm_no_provision.host == C.HOST
    assert info.vendor == "Nitrokey GmbH"
    assert info.product == "NetHSM"


def test_state_provision_add_user_metrics_get_metrics(
    nethsm_no_provision: NetHSM,
) -> None:
    """Query the metrics of a NetHSM.

    This command requires authentication as a user with the Metrics role.
    Fixme: Asserts True on linux and False on Macos due to lack of a few
    metrics in metrics"""
    provision(nethsm_no_provision)
    add_user(nethsm_no_provision, C.METRICS_USER)

    with connect(C.METRICS_USER) as nethsm:
        data = nethsm.get_metrics()
        metrics = [
            "gc compactions",
            "gc major bytes",
            "gc major collections",
            "gc minor collections",
            "http response 200",
            "http response 201",
            "http response 204",
            "http response time",
            "http response total",
            "kv write",
            "log errors",
            "log warnings",
            "uptime",
        ]
        for metric in metrics:
            assert metric in data


def test_state_provision_unlock_lock(nethsm_no_provision: NetHSM) -> None:
    """Bring an operational NetHSM into locked state.

    This command requires authentication as a user with the Administrator
    role."""
    provision(nethsm_no_provision)
    unlock(nethsm_no_provision, C.UNLOCK_PASSPHRASE)

    lock(nethsm_no_provision)


def test_state_provision_lock_unlock(nethsm_no_provision: NetHSM) -> None:
    """Bring a locked NetHSM into operational state."""
    provision(nethsm_no_provision)
    lock(nethsm_no_provision)

    unlock(nethsm_no_provision, C.UNLOCK_PASSPHRASE)


def test_state_provision_add_user_get_random_data(nethsm_no_provision: NetHSM) -> None:
    """Retrieve random bytes from the NetHSM as a Base64 string.

    This command requires authentication as a user with the Operator role."""
    provision(nethsm_no_provision)
    add_user(nethsm_no_provision, C.OPERATOR_USER)

    with connect(C.OPERATOR_USER) as nethsm:
        random_data1 = nethsm.get_random_data(100)
        random_data2 = nethsm.get_random_data(100)
        random_data3 = nethsm.get_random_data(100)

        assert len(random_data1.decode()) == 100
        assert len(random_data2.decode()) == 100
        assert len(random_data3.decode()) == 100

        assert random_data1 != random_data2
        assert random_data1 != random_data3
        assert random_data2 != random_data3
