import pytest
from conftest import Constants as C
from conftest import UserData
from utilities import add_user, connect

from nethsm import NetHSM, NetHSMError

"""######################### Preparation for the Tests #########################

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


def add_users(nethsm: NetHSM) -> None:
    """Create a new user on the NetHSM. Tests adding every Role.

    If the real name, role or passphrase are not specified, they have to be
    specified interactively.  If the user ID is not set, it is generated by the
    NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    add_user(nethsm, C.ADMINISTRATOR_USER)
    add_user(nethsm, C.OPERATOR_USER)
    add_user(nethsm, C.METRICS_USER)
    add_user(nethsm, C.BACKUP_USER)


def delete_users_not_admin(nethsm: NetHSM) -> None:
    user_ids = nethsm.list_users()
    if len(user_ids) > 1:
        for user_id in user_ids:
            user = nethsm.get_user(user_id=user_id)
            if user.user_id != "admin":
                nethsm.delete_user(user.user_id)


def change_passphrase_with_admin(nethsm: NetHSM, user_id: str) -> None:
    nethsm.set_passphrase(user_id, C.PASSPHRASE_CHANGED)


def login_user_get_state(username: UserData) -> None:
    with connect(username) as nethsm:
        nethsm.get_state()


def login_user_with_wrong_passphrase(user: UserData) -> None:
    with connect(user) as nethsm:
        with pytest.raises(NetHSMError):
            nethsm.get_user(user_id=user.user_id)


def add_operator_tags(nethsm: NetHSM) -> None:
    nethsm.add_operator_tag(user_id=C.OPERATOR_USER.user_id, tag=C.TAG1)
    nethsm.add_operator_tag(user_id=C.OPERATOR_USER.user_id, tag=C.TAG2)
    nethsm.add_operator_tag(user_id=C.OPERATOR_USER.user_id, tag=C.TAG3)


"""######################### Start of Tests #########################"""


def test_list_get_delete_add_users(nethsm: NetHSM) -> None:

    delete_users_not_admin(nethsm)
    add_users(nethsm)
    user_ids = nethsm.list_users()
    remaining = C.USERS_LIST.copy()
    for user_id in user_ids:
        user = nethsm.get_user(user_id=user_id)

        for i in range(len(remaining)):
            if user.user_id == remaining[i].user_id:
                assert user.real_name == remaining[i].real_name
                assert user.role.value == remaining[i].role.value
                remaining.pop(i)
                break

    assert remaining == []


def test_get_user_admin(nethsm: NetHSM) -> None:
    """Query the real name and role for a user ID on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    user = nethsm.get_user(user_id=C.ADMIN_USER.user_id)
    assert user.user_id == C.ADMIN_USER.user_id
    assert user.real_name == C.ADMIN_USER.real_name
    assert user.role.value == C.ADMIN_USER.role.value


# @pytest.mark.xfail(reason="connect() doesn't require correct passphrase yet")
def test_add_users_set_passphrases_connect(nethsm: NetHSM) -> None:
    """Set the passphrase for the user with the given ID (or the current user).

    This command requires authentication as a user with the Administrator or
    Operator role.  Users with the Operator role can only change their own
    passphrase.
    Todo: Todo: Edit following example into connect() so it checks for
    username and password:"""
    """username = ctx.obj["NETHSM_USERNAME"]
    password = ctx.obj["NETHSM_PASSWORD"]"""
    add_users(nethsm)

    """Set with a Administrator User the passphrase of other users"""
    change_passphrase_with_admin(nethsm, C.ADMINISTRATOR_USER.user_id)
    change_passphrase_with_admin(nethsm, C.BACKUP_USER.user_id)
    change_passphrase_with_admin(nethsm, C.METRICS_USER.user_id)
    change_passphrase_with_admin(nethsm, C.OPERATOR_USER.user_id)

    """Login with every user with correct passphrase"""
    login_user_get_state(C.ADMINISTRATOR_USER)
    login_user_get_state(C.BACKUP_USER)
    login_user_get_state(C.METRICS_USER)
    login_user_get_state(C.OPERATOR_USER)

    """Login with every user with incorrect passphrase
    Works not as intended because of this test implementation"""
    login_user_with_wrong_passphrase(C.ADMINISTRATOR_USER)
    login_user_with_wrong_passphrase(C.BACKUP_USER)
    login_user_with_wrong_passphrase(C.METRICS_USER)
    login_user_with_wrong_passphrase(C.OPERATOR_USER)

    "Set with Operator user the passphrase of another user"
    with connect(C.OPERATOR_USER) as nethsm:
        with pytest.raises(NetHSMError):
            nethsm.set_passphrase(C.METRICS_USER.user_id, C.PASSPHRASE_CHANGED)

    "Set with another user which do not have Administrator or Operator Role"
    with connect(C.BACKUP_USER) as nethsm:
        with pytest.raises(NetHSMError):
            nethsm.set_passphrase(C.BACKUP_USER.user_id, C.PASSPHRASE_CHANGED)


def test_add_delete_user_administrator(nethsm: NetHSM) -> None:
    """Delete the user with the given user ID on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        add_user(nethsm, C.ADMINISTRATOR_USER)
    except NetHSMError:
        pass

    nethsm.delete_user(C.ADMINISTRATOR_USER.user_id)
    with pytest.raises(NetHSMError):
        nethsm.get_user(user_id=C.ADMINISTRATOR_USER.user_id)


def test_add_operator_tags(nethsm: NetHSM) -> None:
    """Add a tag for an operator user on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        add_user(nethsm, C.OPERATOR_USER)
    except NetHSMError:
        pass
    add_operator_tags(nethsm)


def test_add_list_operator_tags(nethsm: NetHSM) -> None:
    """List the tags for an operator user ID on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        add_user(nethsm, C.OPERATOR_USER)
    except NetHSMError:
        pass
    try:
        add_operator_tags(nethsm)
    except NetHSMError:
        pass
    tags = nethsm.list_operator_tags(user_id=C.OPERATOR_USER.user_id)
    if tags:
        for tag in tags:
            assert str(tag) in C.TAGS


def test_add_delete_list_operator_tags(nethsm: NetHSM) -> None:
    """Delete a tag for an operator user on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        add_user(nethsm, C.OPERATOR_USER)
    except NetHSMError:
        pass
    try:
        add_operator_tags(nethsm)
    except NetHSMError:
        pass

    nethsm.delete_operator_tag(user_id=C.OPERATOR_USER.user_id, tag=C.TAG1)
    nethsm.delete_operator_tag(user_id=C.OPERATOR_USER.user_id, tag=C.TAG2)
    tag = nethsm.list_operator_tags(user_id=C.OPERATOR_USER.user_id)
    assert C.TAG1 not in tag and C.TAG2 not in tag


def test_delete_self(nethsm: NetHSM) -> None:
    with pytest.raises(NetHSMError, match="Bad Request"):
        nethsm.delete_user("admin")

    # cannot use ADMINISTRATOR_USER here as we are rate-limited from a previous test
    # add_user(nethsm, C.ADMINISTRATOR_USER)
    # with connect(C.ADMINISTRATOR_USER) as nethsm:
    #     with pytest.raises(NetHSMError, match="Bad Request"):
    #         nethsm.delete_user(C.ADMINISTRATOR_USER.user_id)
