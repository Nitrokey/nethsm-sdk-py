import random
import string
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

import pytest
from conftest import Constants as C

import nethsm
from nethsm import Authentication, KeyMechanism, KeyType, NetHSM, NetHSMError, Role


@dataclass
class User:
    user_id: str
    passphrase: str


@contextmanager
def login(user: User) -> Iterator[NetHSM]:
    auth = Authentication(user.user_id, user.passphrase)
    with nethsm.connect(C.HOST, auth, C.VERIFY_TLS) as n:
        yield n


def add_user(
    n: NetHSM,
    user_id: str,
    real_name: str,
    role: Role,
    namespace: Optional[str] = None,
    passphrase: Optional[str] = None,
) -> User:
    if passphrase is None:
        passphrase_len = random.randint(10, 40)
        passphrase = "".join(
            random.choices(string.ascii_letters + string.digits, k=passphrase_len)
        )
    n.add_user(
        user_id=user_id,
        real_name=real_name,
        role=role,
        namespace=namespace,
        passphrase=passphrase,
    )
    return User(user_id=user_id, passphrase=passphrase)


def test_keys(nethsm: NetHSM) -> None:
    user = add_user(
        nethsm,
        user_id="test",
        namespace="ns",
        real_name="Test",
        role=Role.ADMINISTRATOR,
    )

    assert set(nethsm.list_users()) == {"admin", "test"}
    assert nethsm.list_namespaces() == []

    with login(user) as nethsm_ns:
        with pytest.raises(NetHSMError, match="Access denied"):
            nethsm_ns.list_keys()
        with pytest.raises(NetHSMError, match="Access denied"):
            nethsm_ns.generate_key(KeyType.RSA, [KeyMechanism.RSA_DECRYPTION_RAW], 2048)

    nethsm.add_namespace("ns")
    assert nethsm.list_namespaces() == ["ns"]

    key_id_root = nethsm.generate_key(
        KeyType.RSA, [KeyMechanism.RSA_DECRYPTION_RAW], 2048
    )
    assert nethsm.list_keys() == [key_id_root]

    with login(user) as nethsm_ns:
        assert nethsm_ns.list_keys() == []
        key_id_ns = nethsm_ns.generate_key(
            KeyType.RSA, [KeyMechanism.RSA_DECRYPTION_RAW], 2048
        )
        assert nethsm_ns.list_keys() == [key_id_ns]

    assert nethsm.list_keys() == [key_id_root]

    with login(user) as nethsm_ns:
        with pytest.raises(NetHSMError, match="Access denied"):
            nethsm_ns.delete_namespace("ns")

    with pytest.raises(NetHSMError, match="Access denied"):
        nethsm.delete_user("test")

    nethsm.delete_namespace("ns")
    assert nethsm.list_namespaces() == []
    assert set(nethsm.list_users()) == {"admin", "test"}
    assert nethsm.get_user_namespace("test") == "ns"
    assert nethsm.list_namespaces() == []

    with login(user) as nethsm_ns:
        with pytest.raises(NetHSMError, match="Access denied"):
            nethsm_ns.generate_key(KeyType.RSA, [KeyMechanism.RSA_DECRYPTION_RAW], 2048)
        with pytest.raises(NetHSMError, match="Access denied"):
            nethsm_ns.list_keys()

    nethsm.delete_user("test")
    assert nethsm.list_users() == ["admin"]


def test_config(nethsm: NetHSM) -> None:
    # R-Admin should be able to access config
    nethsm.get_config_logging()

    # N-Admin should not be able to access config
    user = add_user(
        nethsm,
        user_id="admin2",
        namespace="ns",
        real_name="N-Admin",
        role=Role.ADMINISTRATOR,
    )
    with login(user) as nethsm:
        with pytest.raises(NetHSMError, match="Access denied"):
            nethsm.get_config_logging()
