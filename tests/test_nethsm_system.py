import datetime
import os

import pytest
from conftest import Constants as C
from test_nethsm_keys import generate_key
from utilities import (
    Container,
    add_user,
    connect,
    encrypt_rsa,
    provision,
    set_backup_passphrase,
    update,
)

from nethsm import Base64, NetHSM, NetHSMError
from nethsm.backup import Backup, EncryptedBackup

"""######################### Preparation for the Tests #########################

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


"""######################### Start of Tests #########################"""


def test_provision_system_info(nethsm: NetHSM) -> None:
    """Get system information for a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    info = nethsm.get_system_info()
    assert len(info.firmware_version) > 0
    assert len(info.software_version) > 0
    assert len(info.hardware_version) > 0
    # build tag should be vx.y with an optional suffix, so at least length 4
    assert len(info.build_tag) >= 4


def test_passphrase_add_user_retrieve_backup(nethsm: NetHSM) -> None:
    """Make a backup of a NetHSM instance and write it to a file.

    This command requires authentication as a user with the Backup role."""

    set_backup_passphrase(nethsm)
    add_user(nethsm, C.BACKUP_USER)
    add_user(nethsm, C.OPERATOR_USER)

    generate_key(nethsm)
    assert nethsm.list_keys() == [C.KEY_ID_GENERATED]

    key = nethsm.get_key_public_key(C.KEY_ID_GENERATED)
    encrypted = encrypt_rsa(key, C.DATA)
    with open(C.FILENAME_ENCRYPTED, "wb") as f:
        f.write(encrypted)

    with connect(C.BACKUP_USER) as nethsm:
        if os.path.exists(C.FILENAME_BACKUP):
            os.remove(C.FILENAME_BACKUP)
        data = nethsm.backup()
        backup = EncryptedBackup.parse(data).decrypt(C.BACKUP_PASSPHRASE)
        assert f"/key/{C.KEY_ID_GENERATED}" in backup.data
        try:
            with open(C.FILENAME_BACKUP, "xb") as f:
                f.write(data)
        except OSError as e:
            print(e, type(e))
            assert False


def test_factory_reset(container: Container, nethsm: NetHSM) -> None:
    """Perform a factory reset for a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    nethsm.factory_reset()
    container.restart()

    # make sure that we really cleared the data
    assert nethsm.get_state().value == "Unprovisioned"
    provision(nethsm)
    assert nethsm.list_keys() == []

    nethsm.factory_reset()
    container.restart()


def test_state_restore(nethsm: NetHSM) -> None:
    """Restore a backup of a NetHSM instance from a file.

    If the system time is not set, the current system time is used."""

    system_time = datetime.datetime.now(datetime.timezone.utc)
    assert nethsm.get_state().value == "Unprovisioned"

    # We repeat the restore call to debug a problem with the restore endpoint in the CI.
    # See this issue for more information:
    # https://github.com/Nitrokey/nethsm-sdk-py/issues/93

    successful_try = None
    last_exception = None
    for i in range(10):
        try:
            with open(C.FILENAME_BACKUP, "rb") as f:
                nethsm.restore(f, C.BACKUP_PASSPHRASE, system_time)
            successful_try = i
        except NetHSMError as e:
            last_exception = e
            continue

    if successful_try != 0:
        print(f"successful try: {successful_try}")
        assert last_exception
        raise last_exception

    nethsm.unlock(C.UNLOCK_PASSPHRASE)

    assert nethsm.list_keys() == [C.KEY_ID_GENERATED]

    with open(C.FILENAME_ENCRYPTED, "rb") as f:
        encrypted = f.read()

    # see test_decrypt in test_nethsm_keys
    with connect(C.OPERATOR_USER) as nethsm:
        decrypt = nethsm.decrypt(
            C.KEY_ID_GENERATED,
            Base64.encode(encrypted),
            C.MODE,
        )
        assert decrypt.decode().decode() == C.DATA


def test_state_provision_update(container: Container, nethsm: NetHSM) -> None:
    """Load an update to a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    container.restart()

    provision(nethsm)

    update(nethsm)


def test_state_provision_update_cancel_update(container: Container, nethsm: NetHSM) -> None:
    """Cancel a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    container.restart()

    provision(nethsm)

    update(nethsm)
    nethsm.cancel_update()


def test_update_commit_update(container: Container, nethsm: NetHSM) -> None:
    """Commit a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    container.restart()

    provision(nethsm)

    update(nethsm)
    nethsm.commit_update()


def test_provision_reboot(container: Container, nethsm: NetHSM) -> None:
    """Reboot a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    container.restart()

    provision(nethsm)

    nethsm.reboot()


def test_provision_shutdown(container: Container, nethsm: NetHSM) -> None:
    """Shutdown a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    container.restart()

    provision(nethsm)

    nethsm.shutdown()
