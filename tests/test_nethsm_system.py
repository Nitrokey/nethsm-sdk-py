import base64
import datetime
import os

import pytest
from conftest import Constants as C
from test_nethsm_keys import generate_key
from utilities import nethsm  # noqa: F401
from utilities import (
    add_user,
    connect,
    encrypt_rsa,
    provision,
    set_backup_passphrase,
    start_nethsm,
    update,
)

from nethsm import NetHSM
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
    role.
    TODO: do not rely on string constants, as nethsm:testing version changes
    """
    info = nethsm.get_system_info()
    assert type(info.firmware_version) is str
    assert type(info.software_version) is str
    assert type(info.hardware_version) is str
    assert type(info.build_tag) is str
    assert len(info.build_tag) == C.BUILD_TAG_LEN

    # fixme: this changes between the NetHSM instances


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


def test_factory_reset(nethsm: NetHSM) -> None:
    """Perform a factory reset for a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    nethsm.factory_reset()
    start_nethsm()

    # make sure that we really cleared the data
    assert nethsm.get_state().value == "Unprovisioned"
    provision(nethsm)
    assert nethsm.list_keys() == []

    nethsm.factory_reset()
    start_nethsm()


def test_state_restore(nethsm: NetHSM) -> None:
    """Restore a backup of a NetHSM instance from a file.

    If the system time is not set, the current system time is used."""

    system_time = datetime.datetime.now(datetime.timezone.utc)
    assert nethsm.get_state().value == "Unprovisioned"

    try:
        with open(C.FILENAME_BACKUP, "rb") as f:
            nethsm.restore(f, C.BACKUP_PASSPHRASE, system_time)
            nethsm.unlock(C.UNLOCK_PASSPHRASE)
    except OSError as e:
        print(e, type(e))
        assert False

    assert nethsm.list_keys() == [C.KEY_ID_GENERATED]

    with open(C.FILENAME_ENCRYPTED, "rb") as f:
        encrypted = f.read()

    # see test_decrypt in test_nethsm_keys
    with connect(C.OPERATOR_USER) as nethsm:
        decrypt = nethsm.decrypt(
            C.KEY_ID_GENERATED,
            base64.b64encode(encrypted).decode(),
            C.MODE,
            "arstasrta",
        )
        assert base64.b64decode(decrypt).decode() == C.DATA


def test_state_provision_update(nethsm: NetHSM) -> None:
    """Load an update to a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    update(nethsm)


def test_state_provision_update_cancel_update(nethsm: NetHSM) -> None:
    """Cancel a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    update(nethsm)
    nethsm.cancel_update()


def test_update_commit_update(nethsm: NetHSM) -> None:
    """Commit a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    update(nethsm)
    nethsm.commit_update()


def test_provision_reboot(nethsm: NetHSM) -> None:
    """Reboot a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    nethsm.reboot()


def test_provision_shutdown(nethsm: NetHSM) -> None:
    """Shutdown a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    nethsm.shutdown()
