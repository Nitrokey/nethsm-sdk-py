from typing import Any, Protocol, Type

import pytest

import nethsm
from nethsm.client.components.schema.decrypt_mode import DecryptModeEnums
from nethsm.client.components.schema.encrypt_mode import EncryptModeEnums
from nethsm.client.components.schema.key_mechanism import KeyMechanismEnums
from nethsm.client.components.schema.key_type import KeyTypeEnums
from nethsm.client.components.schema.log_level import LogLevelEnums
from nethsm.client.components.schema.sign_mode import SignModeEnums
from nethsm.client.components.schema.switch import SwitchEnums
from nethsm.client.components.schema.system_state import SystemStateEnums
from nethsm.client.components.schema.tls_key_type import TlsKeyTypeEnums
from nethsm.client.components.schema.user_role import UserRoleEnums
from nethsm.client.schemas import classproperty


class Enum(Protocol):
    @staticmethod
    def from_string(s: str) -> "Enum":
        ...


def check_enum(our_enum: Type[Enum], api_enum: Type[Any]) -> None:
    for (key, cp) in api_enum.__dict__.items():
        if "_" in key:
            continue
        assert isinstance(cp, classproperty)
        value = cp.__get__(obj=None, cls=api_enum)
        enum_value = our_enum.from_string(value)
        assert isinstance(enum_value, our_enum)
        assert getattr(enum_value, "value", None) == value

    with pytest.raises(ValueError):
        our_enum.from_string("foobar")


def test_role() -> None:
    check_enum(nethsm.Role, UserRoleEnums)


def test_state() -> None:
    check_enum(nethsm.State, SystemStateEnums)


def test_log_level() -> None:
    check_enum(nethsm.LogLevel, LogLevelEnums)


def test_unattended_boot_status() -> None:
    check_enum(nethsm.UnattendedBootStatus, SwitchEnums)


def test_key_type() -> None:
    check_enum(nethsm.KeyType, KeyTypeEnums)


def test_key_mechanism() -> None:
    check_enum(nethsm.KeyMechanism, KeyMechanismEnums)


def test_encrypt_mode() -> None:
    check_enum(nethsm.EncryptMode, EncryptModeEnums)


def test_decrypt_mode() -> None:
    check_enum(nethsm.DecryptMode, DecryptModeEnums)


def test_sign_mode() -> None:
    check_enum(nethsm.SignMode, SignModeEnums)


def test_tls_key_type() -> None:
    check_enum(nethsm.TlsKeyType, TlsKeyTypeEnums)
