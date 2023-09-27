import datetime
import os

import docker
import pytest
from conftest import Constants as C
from utilities import nethsm  # noqa: F401
from utilities import (
    add_user,
    connect,
    start_nethsm,
    provision,
    set_backup_passphrase,
    update,
)

"""######################### Preparation for the Tests #########################

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


"""######################### Start of Tests #########################"""


def test_provision_system_info(nethsm):
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


def test_passphrase_add_user_retrieve_backup(nethsm):
    """Make a backup of a NetHSM instance and write it to a file.

    This command requires authentication as a user with the Backup role.

    Todo: Further Optimization contains reading all the contents of the Nethsm
    the do the backup and restore and then read once again all the contents
    to compare before to later"""
    set_backup_passphrase(nethsm)
    add_user(nethsm, C.BackupUser)

    with connect(C.BackupUser) as nethsm:
        if os.path.exists(C.FILENAME_BACKUP):
            os.remove(C.FILENAME_BACKUP)
        data = nethsm.backup()
        try:
            with open(C.FILENAME_BACKUP, "xb") as f:
                f.write(data)
        except OSError as e:
            print(e, type(e))
            assert False


def test_factory_reset(nethsm):
    """Perform a factory reset for a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    nethsm.factory_reset()


@pytest.mark.xfail(reason="NetHSM backup is currently not working")
def test_state_restore(nethsm):
    """Restore a backup of a NetHSM instance from a file.

    If the system time is not set, the current system time is used."""
    start_nethsm()

    system_time = datetime.datetime.now(datetime.timezone.utc)
    if nethsm.get_state().value == "Unprovisioned":
        try:
            with open(C.FILENAME_BACKUP, "rb") as f:
                nethsm.restore(f, C.BACKUP_PASSPHRASE, system_time)
                nethsm.unlock(C.UNLOCK_PASSPHRASE)
        except OSError as e:
            print(e, type(e))
            assert False
    else:
        assert False


def test_state_provision_update(nethsm):
    """Load an update to a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    update(nethsm)


def test_state_provision_update_cancel_update(nethsm):
    """Cancel a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    update(nethsm)
    nethsm.cancel_update()


def test_update_commit_update(nethsm):
    """Commit a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    update(nethsm)
    nethsm.commit_update()


def test_provision_reboot(nethsm):
    """Reboot a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    nethsm.reboot()

    try:
        start_nethsm()
    except docker.errors.APIError:
        pass


def test_provision_shutdown(nethsm):
    """Shutdown a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    start_nethsm()

    provision(nethsm)

    nethsm.shutdown()

    try:
        start_nethsm()
    except docker.errors.APIError:
        pass
