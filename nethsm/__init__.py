# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
"""Python Library to manage NetHSM(s)."""

__version__ = "0.4.0"

import contextlib
import enum
import json
import re
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from io import BufferedReader
from typing import TYPE_CHECKING, Any, Iterator, Literal, Mapping, Optional, Union, cast
from urllib.parse import urlencode

import urllib3
from urllib3 import HTTPResponse, _collections
from urllib3._collections import HTTPHeaderDict

# Avoid direct imports from .client at runtime to reduce the module load time
if TYPE_CHECKING:
    from .client import ApiException
    from .client.apis.tags.default_api import DefaultApi


class Role(enum.Enum):
    ADMINISTRATOR = "Administrator"
    OPERATOR = "Operator"
    METRICS = "Metrics"
    BACKUP = "Backup"

    @staticmethod
    def from_string(s: str) -> "Role":
        for role in Role:
            if role.value == s:
                return role
        raise ValueError(f"Unsupported user role {s}")


class State(enum.Enum):
    UNPROVISIONED = "Unprovisioned"
    LOCKED = "Locked"
    OPERATIONAL = "Operational"

    @staticmethod
    def from_string(s: str) -> "State":
        for state in State:
            if state.value == s:
                return state
        raise ValueError(f"Unsupported system state {s}")


class LogLevel(enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @staticmethod
    def from_string(s: str) -> "LogLevel":
        for log_level in LogLevel:
            if log_level.value == s:
                return log_level
        raise ValueError(f"Unsupported log level {s}")


class UnattendedBootStatus(enum.Enum):
    ON = "on"
    OFF = "off"


class KeyType(enum.Enum):
    RSA = "RSA"
    CURVE25519 = "Curve25519"
    EC_P224 = "EC_P224"
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"
    EC_P521 = "EC_P521"
    GENERIC = "Generic"

    @staticmethod
    def from_string(s: str) -> "KeyType":
        for key_type in KeyType:
            if key_type.value == s:
                return key_type
        raise ValueError(f"Unsupported key type {s}")


KeyTypeLitteral = Literal[
    "RSA", "Curve25519", "EC_P224", "EC_P256", "EC_P384", "EC_P521", "Generic"
]


class KeyMechanism(enum.Enum):
    RSA_DECRYPTION_RAW = "RSA_Decryption_RAW"
    RSA_DECRYPTION_PKCS1 = "RSA_Decryption_PKCS1"
    RSA_DECRYPTION_OAEP_MD5 = "RSA_Decryption_OAEP_MD5"
    RSA_DECRYPTION_OAEP_SHA1 = "RSA_Decryption_OAEP_SHA1"
    RSA_DECRYPTION_OAEP_SHA224 = "RSA_Decryption_OAEP_SHA224"
    RSA_DECRYPTION_OAEP_SHA256 = "RSA_Decryption_OAEP_SHA256"
    RSA_DECRYPTION_OAEP_SHA384 = "RSA_Decryption_OAEP_SHA384"
    RSA_DECRYPTION_OAEP_SHA512 = "RSA_Decryption_OAEP_SHA512"
    RSA_SIGNATURE_PKCS1 = "RSA_Signature_PKCS1"
    RSA_SIGNATURE_PSS_MD5 = "RSA_Signature_PSS_MD5"
    RSA_SIGNATURE_PSS_SHA1 = "RSA_Signature_PSS_SHA1"
    RSA_SIGNATURE_PSS_SHA224 = "RSA_Signature_PSS_SHA224"
    RSA_SIGNATURE_PSS_SHA256 = "RSA_Signature_PSS_SHA256"
    RSA_SIGNATURE_PSS_SHA384 = "RSA_Signature_PSS_SHA384"
    RSA_SIGNATURE_PSS_SHA512 = "RSA_Signature_PSS_SHA512"
    EDDSA_SIGNATURE = "EdDSA_Signature"
    ECDSA_SIGNATURE = "ECDSA_Signature"
    AES_ENCRYPTION_CBC = "AES_Encryption_CBC"
    AES_DECRYPTION_CBC = "AES_Decryption_CBC"


KeyMechanismLiteral = Literal[
    "RSA_Decryption_RAW",
    "RSA_Decryption_PKCS1",
    "RSA_Decryption_OAEP_MD5",
    "RSA_Decryption_OAEP_SHA1",
    "RSA_Decryption_OAEP_SHA224",
    "RSA_Decryption_OAEP_SHA256",
    "RSA_Decryption_OAEP_SHA384",
    "RSA_Decryption_OAEP_SHA512",
    "RSA_Signature_PKCS1",
    "RSA_Signature_PSS_MD5",
    "RSA_Signature_PSS_SHA1",
    "RSA_Signature_PSS_SHA224",
    "RSA_Signature_PSS_SHA256",
    "RSA_Signature_PSS_SHA384",
    "RSA_Signature_PSS_SHA512",
    "EdDSA_Signature",
    "ECDSA_Signature",
    "AES_Encryption_CBC",
    "AES_Decryption_CBC",
]


class EncryptMode(enum.Enum):
    AES_CBC = "AES_CBC"


class DecryptMode(enum.Enum):
    RAW = "RAW"
    PKCS1 = "PKCS1"
    OAEP_MD5 = "OAEP_MD5"
    OAEP_SHA1 = "OAEP_SHA1"
    OAEP_SHA224 = "OAEP_SHA224"
    OAEP_SHA256 = "OAEP_SHA256"
    OAEP_SHA384 = "OAEP_SHA384"
    OAEP_SHA512 = "OAEP_SHA512"
    AES_CBC = "AES_CBC"


class SignMode(enum.Enum):
    PKCS1 = "PKCS1"
    PSS_MD5 = "PSS_MD5"
    PSS_SHA1 = "PSS_SHA1"
    PSS_SHA224 = "PSS_SHA224"
    PSS_SHA256 = "PSS_SHA256"
    PSS_SHA384 = "PSS_SHA384"
    PSS_SHA512 = "PSS_SHA512"
    EDDSA = "EdDSA"
    ECDSA = "ECDSA"


class TlsKeyType(enum.Enum):
    RSA = "RSA"
    CURVE25519 = "Curve25519"
    EC_P224 = "EC_P224"
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"
    EC_P521 = "EC_P521"


@dataclass
class SystemInfo:
    firmware_version: str
    software_version: str
    hardware_version: str
    build_tag: str


@dataclass
class User:
    user_id: str
    real_name: str
    role: Role


@dataclass
class Key:
    key_id: str
    mechanisms: list[str]
    type: KeyType
    operations: int
    tags: Optional[list[str]]
    modulus: Optional[str]
    public_exponent: Optional[str]
    data: Optional[str]


@dataclass
class LoggingConfig:
    ip_address: str
    log_level: LogLevel
    port: int


@dataclass
class NetworkConfig:
    gateway: str
    ip_address: str
    netmask: str


def _handle_exception(
    e: Exception,
    messages: dict[int, str] = {},
    roles: list[Role] = [],
    state: Optional[State] = None,
) -> None:
    from .client import ApiException

    if isinstance(e, ApiException):
        _handle_api_exception(e, messages, roles, state)
    elif isinstance(e, urllib3.exceptions.MaxRetryError):
        if isinstance(e.reason, urllib3.exceptions.SSLError):
            raise NetHSMRequestError(RequestErrorType.SSL_ERROR, e)
        raise NetHSMRequestError(RequestErrorType.OTHER, e)
    else:
        raise e


def _handle_api_exception(
    e: "ApiException[Any]",
    messages: dict[int, str] = {},
    roles: list[Role] = [],
    state: Optional[State] = None,
) -> None:
    if e.status in messages:
        message = messages[e.status]
        raise NetHSMError(message)

    if e.status == 401 and roles:
        message = "Unauthorized -- invalid username or password"
    elif e.status == 403 and roles:
        roles_str = [role.value for role in roles]
        message = "Access denied -- this operation requires the role " + " or ".join(
            roles_str
        )
    elif e.status == 405:
        # 405 "Method Not Allowed" mostly happens when the UserID or KeyID contains a character
        # - that ends the path of the URL like a question mark '?' :
        #   /api/v1/keys/?/cert will hit the keys listing endpoint instead of the key/{KeyID}/cert endpoint
        # - that doesn't count as a path parameter like a slash '/' :
        #   /api/v1/keys///cert will be interpreted as /api/v1/keys/cert with cert as the KeyID
        message = "The ID you provided contains invalid characters"
    elif e.status == 406:
        message = "Invalid content type requested"
    elif e.status == 412 and state:
        message = f"Precondition failed -- this operation can only be used on a NetHSM in the state {state.value}"
    elif e.status == 429:
        message = (
            "Too many requests -- you may have tried the wrong credentials too often"
        )
    else:
        message = f"Unexpected API error {e.status}: {e.reason}"

    if e.api_response:
        try:
            body = None
            # "custom" requests
            if hasattr(e.api_response, "text") and e.api_response.text != "":
                body = json.loads(e.api_response.text)
            # generated code
            elif (
                hasattr(e.api_response, "response")
                and e.api_response.response.data != ""
            ):
                body = json.loads(e.api_response.response.data)
            if body is not None and "message" in body:
                message += "\n" + body["message"]
        except json.JSONDecodeError:
            pass

    raise NetHSMError(message)


class NetHSMError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class RequestErrorType(enum.Enum):
    SSL_ERROR = "SSL_ERROR"
    OTHER = "OTHER"


class NetHSMRequestError(Exception):
    def __init__(self, type: RequestErrorType, reason: Exception) -> None:
        super().__init__(f"NetHSM API request error: {type.value} {reason}")
        self.type = type
        self.reason = reason


class NetHSM:
    def __init__(
        self,
        host: str,
        version: str,
        username: str,
        password: str,
        verify_tls: bool = True,
    ) -> None:
        from .client import ApiClient, ApiConfiguration
        from .client.components.security_schemes import security_scheme_basic
        from .client.configurations.api_configuration import (
            SecuritySchemeInfo,
            ServerInfo,
        )
        from .client.servers.server_0 import Server0, VariablesDict

        self.host = host
        self.version = version
        self.username = username
        self.password = password

        security_info = SecuritySchemeInfo(
            {
                "basic": security_scheme_basic.Basic(
                    user_id=username,
                    password=password,
                )
            }
        )

        server_config = ServerInfo(
            {"servers/0": Server0(variables=VariablesDict(host=host, version=version))}
        )
        config = ApiConfiguration(
            server_info=server_config, security_scheme_info=security_info
        )
        config.verify_ssl = verify_tls
        self.client = ApiClient(configuration=config)

        if not verify_tls:
            urllib3.disable_warnings()

    def close(self) -> None:
        self.client.close()  # type: ignore[no-untyped-call]

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, str]] = None,
        data: Optional[BufferedReader] = None,
        mime_type: Optional[str] = "application/json",
        json_obj: Optional[Any] = None,
    ) -> HTTPResponse:
        from .client import ApiException
        from .client.api_response import ApiResponseWithoutDeserialization

        url = f"https://{self.host}/api/{self.version}/{endpoint}"

        if params:
            url += "?" + urlencode(params)

        headers = _collections.HTTPHeaderDict()
        if mime_type is not None:
            headers["Content-Type"] = mime_type

        # basic auth from self.username and self.password
        if self.username and self.password:
            headers[
                "Authorization"
            ] = f"Basic {b64encode(f'{self.username}:{self.password}'.encode('latin-1')).decode()}"

        body: Union[str, bytes, None] = None
        if data:
            body = data.read(-1)
        elif json_obj:
            encoder = json.JSONEncoder()
            body = encoder.encode(json_obj)

        response = self.get_api().api_client.rest_client.request(
            method=method, url=url, headers=headers, body=body
        )

        if 200 > response.status or response.status > 399:
            api_response = ApiResponseWithoutDeserialization(response=response)
            raise ApiException(
                status=response.status,
                reason=response.reason,
                api_response=api_response,
            )
        return response

    def get_api(self) -> "DefaultApi":
        from .client.apis.tags.default_api import DefaultApi

        return DefaultApi(self.client)

    def get_location(self, headers: HTTPHeaderDict) -> Optional[str]:
        return headers.get("location")

    def get_key_id_from_location(self, headers: HTTPHeaderDict) -> str:
        location = self.get_location(headers)
        if not location:
            raise NetHSMError("Could not determine the ID of the new key")
        key_id_match = re.fullmatch(f"/api/{self.version}/keys/(.*)", location)
        if not key_id_match:
            raise NetHSMError("Could not determine the ID of the new key")
        return key_id_match[1]

    def get_user_id_from_location(self, headers: HTTPHeaderDict) -> str:
        location = self.get_location(headers)
        if not location:
            raise NetHSMError("Could not determine the ID of the new key")
        user_id_match = re.fullmatch(f"/api/{self.version}/users/(.*)", location)
        if not user_id_match:
            raise NetHSMError("Could not determine the ID of the new user")
        return user_id_match[1]

    def unlock(self, passphrase: str) -> None:
        from .client.components.schema.unlock_request_data import UnlockRequestDataDict

        request_body = UnlockRequestDataDict(
            passphrase=passphrase,
        )
        try:
            self.get_api().unlock_post(request_body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.LOCKED,
                messages={
                    # Doc says 400 could happen when the passphrase is invalid?
                    400: "Access denied -- wrong unlock passphrase",
                    403: "Access denied -- wrong unlock passphrase",
                },
            )

    def lock(self) -> None:
        try:
            self.get_api().lock_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def provision(
        self,
        unlock_passphrase: str,
        admin_passphrase: str,
        system_time: Union[str, datetime],
    ) -> None:
        from .client.components.schema.provision_request_data import (
            ProvisionRequestDataDict,
        )

        request_body = ProvisionRequestDataDict(
            unlockPassphrase=unlock_passphrase,
            adminPassphrase=admin_passphrase,
            systemTime=system_time,
        )
        try:
            self.get_api().provision_post(request_body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Malformed request data -- e. g. weak passphrase or invalid time",
                },
            )

    def list_users(self) -> list[str]:
        try:
            response = self.get_api().users_get()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )
        return [item.user for item in response.body]

    def get_user(self, user_id: str) -> User:
        from .client.paths.users_user_id.get.path_parameters import PathParametersDict

        path_params = PathParametersDict(UserID=user_id)
        try:
            response = self.get_api().users_user_id_get(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )
        return User(
            user_id=user_id,
            real_name=response.body.realName,
            role=Role.from_string(response.body.role),
        )

    def add_user(
        self,
        real_name: str,
        role: Literal["Administrator", "Operator", "Metrics", "Backup"],
        passphrase: str,
        user_id: Optional[str] = None,
    ) -> str:
        from .client.components.schema.user_post_data import UserPostDataDict
        from .client.paths.users_user_id.put.path_parameters import PathParametersDict

        body = UserPostDataDict(
            realName=real_name,
            role=role,
            passphrase=passphrase,
        )
        try:
            if user_id:
                path_params = PathParametersDict(UserID=user_id)
                self.get_api().users_user_id_put(path_params=path_params, body=body)
            else:
                response = self.get_api().users_post(body=body)
                user_id = self.get_user_id_from_location(response.response.getheaders())
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                    409: f"Conflict -- a user with the ID {user_id} already exists",
                },
            )
        if user_id is None:
            raise NetHSMError("Could not determine the ID of the new user")
        return user_id

    def delete_user(self, user_id: str) -> None:
        from .client.paths.users_user_id.delete.path_parameters import (
            PathParametersDict,
        )

        try:
            path_params = PathParametersDict(UserID=user_id)
            self.get_api().users_user_id_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )

    def set_passphrase(self, user_id: str, passphrase: str) -> None:
        from .client.components.schema.user_passphrase_post_data import (
            UserPassphrasePostDataDict,
        )
        from .client.paths.users_user_id_passphrase.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id)
        body = UserPassphrasePostDataDict(passphrase=passphrase)
        try:
            self.get_api().users_user_id_passphrase_post(
                path_params=path_params, body=body
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                    404: f"User {user_id} not found",
                },
            )

    def list_operator_tags(self, user_id: str) -> list[str]:
        from .client.paths.users_user_id_tags.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id)
        try:
            response = self.get_api().users_user_id_tags_get(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )
        return list(response.body)

    def add_operator_tag(self, user_id: str, tag: str) -> None:
        from .client.paths.users_user_id_tags_tag.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id, Tag=tag)
        try:
            self.get_api().users_user_id_tags_tag_put(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    304: f"Tag is already present for {user_id}",
                    400: "Invalid tag format or user is not an operator",
                    404: f"User {user_id} not found",
                },
            )

    def delete_operator_tag(self, user_id: str, tag: str) -> None:
        from .client.paths.users_user_id_tags_tag.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id, Tag=tag)
        try:
            self.get_api().users_user_id_tags_tag_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} or tag {tag} not found",
                },
            )

    def add_key_tag(self, key_id: str, tag: str) -> None:
        from .client.paths.keys_key_id_restrictions_tags_tag.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id, Tag=tag)
        try:
            self.get_api().keys_key_id_restrictions_tags_tag_put(
                path_params=path_params
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    304: f"Tag is already present for {key_id}",
                    400: f"Tag {tag} has invalid format",
                    404: f"Key {key_id} not found",
                },
            )

    def delete_key_tag(self, key_id: str, tag: str) -> None:
        from .client.paths.keys_key_id_restrictions_tags_tag.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id, Tag=tag)
        try:
            self.get_api().keys_key_id_restrictions_tags_tag_delete(
                path_params=path_params
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"Key {key_id} or tag {tag} not found",
                },
            )

    def get_info(self) -> tuple[str, str]:
        try:
            response = self.get_api().info_get()
        except Exception as e:
            _handle_exception(e)
        return (response.body.vendor, response.body.product)

    def get_state(self) -> State:
        try:
            response = self.get_api().health_state_get()
        except Exception as e:
            _handle_exception(e)
        return State.from_string(response.body.state)

    def get_random_data(self, n: int) -> str:
        from .client.components.schema.random_request_data import RandomRequestDataDict

        body = RandomRequestDataDict(length=n)
        try:
            response = self.get_api().random_post(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Invalid length. Must be between 1 and 1024",
                },
            )
        return response.body.random

    def get_metrics(self) -> Mapping[str, Any]:
        try:
            response = self.get_api().metrics_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.METRICS])
        return response.body

    def list_keys(self, filter: Optional[str] = None) -> list[str]:
        from .client.paths.keys.get.query_parameters import QueryParametersDict

        try:
            if filter:
                query_params = QueryParametersDict(filter=filter)
                response = self.get_api().keys_get(query_params=query_params)
            else:
                response = self.get_api().keys_get()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
            )
        return [item.key for item in response.body]

    def get_key(self, key_id: str) -> Key:
        from .client.paths.keys_key_id.get.path_parameters import PathParametersDict

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self.get_api().keys_key_id_get(path_params=path_params)
            key = response.body
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )
        return Key(
            key_id=key_id,
            mechanisms=[mechanism for mechanism in key.mechanisms],
            type=KeyType.from_string(key.type),
            operations=key.operations,
            tags=[str(tag) for tag in cast(list[str], key.restrictions["tags"])]
            if "tags" in key.restrictions.keys()
            else None,
            modulus=getattr(key.key, "modulus", None),
            public_exponent=getattr(key.key, "public_exponent", None),
            data=getattr(key.key, "data", None),
        )

    # Get the public key file in PEM format
    def get_key_public_key(self, key_id: str) -> str:
        from .client.paths.keys_key_id_public_pem.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self.get_api().keys_key_id_public_pem_get(
                path_params=path_params, skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )
        return response.response.data.decode("utf-8")

    def add_key(
        self,
        key_id: str,
        type: KeyTypeLitteral,
        mechanisms: list[KeyMechanismLiteral],
        tags: list[str],
        prime_p: Optional[str],
        prime_q: Optional[str],
        public_exponent: Optional[str],
        data: Optional[str],
    ) -> str:
        from .client.components.schema.key_private_data import KeyPrivateDataDict
        from .client.components.schema.key_restrictions import KeyRestrictionsDict
        from .client.components.schema.private_key import PrivateKeyDict
        from .client.components.schema.tag_list import TagListTuple

        # To do: split into different methods for RSA and other key types, or
        # at least change typing accordingly

        if type == "RSA":
            assert prime_p
            assert prime_q
            assert public_exponent
            key_data = KeyPrivateDataDict(
                primeP=prime_p,
                primeQ=prime_q,
                publicExponent=public_exponent,
            )
        else:
            assert data
            key_data = KeyPrivateDataDict(data=data)

        if tags:
            body = PrivateKeyDict(
                type=type,
                mechanisms=mechanisms,
                key=key_data,
                restrictions=KeyRestrictionsDict(
                    tags=TagListTuple([tag for tag in tags])
                ),
            )
        else:
            body = PrivateKeyDict(
                type=type,
                mechanisms=mechanisms,
                key=key_data,
            )

        try:
            if key_id:
                from .client.paths.keys_key_id.put.path_parameters import (
                    PathParametersDict,
                )

                path_params = PathParametersDict(KeyID=key_id)
                self.get_api().keys_key_id_put(
                    path_params=path_params,
                    body=body,
                    content_type="application/json",
                )
            else:
                response = self.get_api().keys_post(
                    body=body,
                    content_type="application/json",
                    skip_deserialization=True,
                )
                key_id = self.get_key_id_from_location(response.response.getheaders())
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- specified properties are invalid",
                    409: f"Conflict -- a key with the ID {key_id} already exists",
                },
            )
        return key_id

    def delete_key(self, key_id: str) -> None:
        from .client.paths.keys_key_id.delete.path_parameters import PathParametersDict

        path_params = PathParametersDict(KeyID=key_id)
        try:
            self.get_api().keys_key_id_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )

    def generate_key(
        self,
        type: KeyTypeLitteral,
        mechanisms: tuple[KeyMechanismLiteral],
        length: int,
        key_id: Optional[str] = None,
    ) -> str:
        from .client.components.schema.key_generate_request_data import (
            KeyGenerateRequestDataDict,
        )
        from .client.components.schema.key_mechanisms import KeyMechanismsTuple

        if key_id:
            body = KeyGenerateRequestDataDict(
                type=type,
                mechanisms=KeyMechanismsTuple(mechanisms),
                length=length,
                id=key_id,
            )
        else:
            body = KeyGenerateRequestDataDict(
                type=type,
                mechanisms=KeyMechanismsTuple(mechanisms),
                length=length,
            )
        try:
            response = self.get_api().keys_generate_post(
                body=body, skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                    409: f"Conflict -- a key with the ID {key_id} already exists",
                },
            )
        return key_id or str(
            self.get_key_id_from_location(response.response.getheaders())
        )

    def get_config_logging(self) -> LoggingConfig:
        try:
            response = self.get_api().config_logging_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return LoggingConfig(
            ip_address=response.body.ipAddress,
            log_level=LogLevel.from_string(response.body.logLevel),
            port=response.body.port,
        )

    def get_config_network(self) -> NetworkConfig:
        try:
            response = self.get_api().config_network_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return NetworkConfig(
            gateway=response.body.gateway,
            ip_address=response.body.ipAddress,
            netmask=response.body.netmask,
        )

    def get_config_time(self) -> str:
        try:
            response = self.get_api().config_time_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body.time

    def get_config_unattended_boot(self) -> str:
        try:
            response = self.get_api().config_unattended_boot_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body.status

    def get_public_key(self) -> str:
        try:
            response = self.get_api().config_tls_public_pem_get(
                skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def get_certificate(self) -> str:
        try:
            response = self.get_api().config_tls_cert_pem_get(skip_deserialization=True)
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def get_key_certificate(self, key_id: str) -> bytes:
        try:
            from .client.paths.keys_key_id_cert.get.path_parameters import (
                PathParametersDict,
            )

            path_params = PathParametersDict(KeyID=key_id)

            response = self.get_api().keys_key_id_cert_get(
                path_params=path_params, skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Certificate for key {key_id} not found",
                    # The API returns a 406 if there is no certificate or if the key does not exist
                    406: f"Certificate for key {key_id} not found",
                },
            )
        return response.response.data

    def set_certificate(self, cert: BufferedReader) -> None:
        try:
            self.request(
                "PUT",
                "config/tls/cert.pem",
                data=cert,
                mime_type="application/x-pem-file",
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad Request -- invalid certificate",
                },
            )

    def set_key_certificate(self, key_id: str, cert: BufferedReader) -> None:
        try:
            from .client.paths.keys_key_id_cert.put.path_parameters import (
                PathParametersDict,
            )

            path_params = PathParametersDict(KeyID=key_id)

            self.get_api().keys_key_id_cert_put(body=cert, path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad Request -- invalid certificate",
                    404: f"Key {key_id} not found",
                    409: f"Conflict -- key {key_id} already has a certificate",
                    415: "Invalid mime type",
                },
            )

    def delete_key_certificate(self, key_id: str) -> None:
        from .client.paths.keys_key_id_cert.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            self.get_api().keys_key_id_cert_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={404: f"There is no certificate for {key_id}."},
            )

    def csr(
        self,
        country: Optional[str] = None,
        state_or_province: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        common_name: Optional[str] = None,
        email_address: Optional[str] = None,
    ) -> str:
        body = {
            "countryName": country,
            "stateOrProvinceName": state_or_province,
            "localityName": locality,
            "organizationName": organization,
            "organizationalUnitName": organizational_unit,
            "commonName": common_name,
            "emailAddress": email_address,
        }
        try:
            response = self.get_api().config_tls_csr_pem_post(
                body=body, skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def generate_tls_key(
        self,
        type: Literal["RSA", "Curve25519", "EC_P224", "EC_P256", "EC_P384", "EC_P521"],
        length: Optional[int] = None,
    ) -> None:
        from .client.components.schema.tls_key_generate_request_data import (
            TlsKeyGenerateRequestDataDict,
        )
        from .client.schemas import Unset

        body = TlsKeyGenerateRequestDataDict(
            type=type,
            length=length if length is not None else Unset(),
        )

        try:
            self.get_api().config_tls_generate_post(body=body)
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])

    def key_csr(
        self,
        key_id: str,
        country: Optional[str] = None,
        state_or_province: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        common_name: Optional[str] = None,
        email_address: Optional[str] = None,
    ) -> str:
        from .client.paths.keys_key_id_csr_pem.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = {
            "countryName": country,
            "stateOrProvinceName": state_or_province,
            "localityName": locality,
            "organizationName": organization,
            "organizationalUnitName": organizational_unit,
            "commonName": common_name,
            "emailAddress": email_address,
        }
        try:
            response = self.get_api().keys_key_id_csr_pem_post(
                path_params=path_params, body=body, skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )
        return response.response.data.decode("utf-8")

    def set_backup_passphrase(
        self, new_passphrase: str, current_passphrase: Optional[str] = None
    ) -> None:
        from .client.components.schema.backup_passphrase_config import (
            BackupPassphraseConfigDict,
        )

        body = BackupPassphraseConfigDict(
            newPassphrase=new_passphrase, currentPassphrase=current_passphrase or ""
        )
        try:
            self.get_api().config_backup_passphrase_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                },
            )

    def set_unlock_passphrase(
        self, new_passphrase: str, current_passphrase: str
    ) -> None:
        from .client.components.schema.unlock_passphrase_config import (
            UnlockPassphraseConfigDict,
        )

        body = UnlockPassphraseConfigDict(
            newPassphrase=new_passphrase, currentPassphrase=current_passphrase
        )
        try:
            self.get_api().config_unlock_passphrase_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                },
            )

    def set_logging_config(
        self,
        ip_address: str,
        port: int,
        log_level: Literal["debug", "info", "warning", "error"],
    ) -> None:
        from .client.components.schema.logging_config import LoggingConfigDict

        body = LoggingConfigDict(ipAddress=ip_address, port=port, logLevel=log_level)
        try:
            self.get_api().config_logging_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                },
            )

    def set_network_config(self, ip_address: str, netmask: str, gateway: str) -> None:
        from .client.components.schema.network_config import NetworkConfigDict

        body = NetworkConfigDict(ipAddress=ip_address, netmask=netmask, gateway=gateway)
        try:
            self.get_api().config_network_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                },
            )

    def set_time(self, time: Union[str, datetime]) -> None:
        from .client.components.schema.time_config import TimeConfigDict

        body = TimeConfigDict(time=time)
        try:
            self.get_api().config_time_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid time format",
                },
            )

    def set_unattended_boot(self, status: Literal["on", "off"]) -> None:
        from .client.components.schema.unattended_boot_config import (
            UnattendedBootConfigDict,
        )

        body = UnattendedBootConfigDict(status=status)
        try:
            self.get_api().config_unattended_boot_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid status setting",
                },
            )

    def get_system_info(self) -> SystemInfo:
        try:
            response = self.get_api().system_info_get()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )
        return SystemInfo(
            firmware_version=response.body.firmwareVersion,
            software_version=response.body.softwareVersion,
            hardware_version=response.body.hardwareVersion,
            build_tag=response.body.softwareBuild,
        )

    def backup(self) -> bytes:
        try:
            response = self.get_api().system_backup_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.BACKUP],
                messages={
                    412: "NetHSM is not Operational or the backup passphrase is not set",
                },
            )
        return response.response.data

    def restore(self, backup: BufferedReader, passphrase: str, time: datetime) -> None:
        try:
            from .client.paths.system_restore.post.request_body.content.multipart_form_data.schema import (
                ArgumentsDict,
                SchemaDict,
            )

            body = SchemaDict(
                arguments=ArgumentsDict(
                    backupPassphrase=passphrase, systemTime=time.isoformat()
                ),
                backup_file=backup,
            )

            self.get_api().system_restore_post(body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Bad request -- backup did not apply",
                },
            )

    def update(self, image: BufferedReader) -> str:
        try:
            response = self.get_api().system_update_post(body=image)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- malformed image",
                    409: "Conflict -- major version downgrade is not allowed",
                },
            )

        # Manually read the release notes from the response body
        json_str = response.response.data.decode("utf-8")
        release_notes = json.loads(json_str)["releaseNotes"]
        assert isinstance(release_notes, str)
        return release_notes

        # # Use this one when the bug is fixed:
        # return response.body.releaseNotes

    def cancel_update(self) -> None:
        try:
            self.get_api().system_cancel_update_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def commit_update(self) -> None:
        try:
            self.get_api().system_commit_update_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def reboot(self) -> None:
        try:
            self.get_api().system_reboot_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def shutdown(self) -> None:
        try:
            self.get_api().system_shutdown_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def factory_reset(self) -> None:
        try:
            self.get_api().system_factory_reset_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def encrypt(
        self, key_id: str, data: str, mode: Literal["AES_CBC"], iv: str
    ) -> tuple[str, str]:
        from .client.components.schema.encrypt_request_data import (
            EncryptRequestDataDict,
        )
        from .client.paths.keys_key_id_encrypt.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = EncryptRequestDataDict(message=data, mode=mode, iv=iv)
        try:
            response = self.get_api().keys_key_id_encrypt_post(
                path_params=path_params, body=body
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. invalid encryption mode, or wrong padding",
                    404: f"Key {key_id} not found",
                },
            )
        return (response.body.encrypted, response.body.iv)

    def decrypt(
        self,
        key_id: str,
        data: str,
        mode: Literal[
            "RAW",
            "PKCS1",
            "OAEP_MD5",
            "OAEP_SHA1",
            "OAEP_SHA224",
            "OAEP_SHA256",
            "OAEP_SHA384",
            "OAEP_SHA512",
            "AES_CBC",
        ],
        iv: str,
    ) -> str:
        from .client.components.schema.decrypt_request_data import (
            DecryptRequestDataDict,
        )
        from .client.paths.keys_key_id_decrypt.post.path_parameters import (
            PathParametersDict,
        )

        body = DecryptRequestDataDict(encrypted=data, mode=mode, iv=iv)

        if len(iv) == 0:
            body = DecryptRequestDataDict(encrypted=data, mode=mode)

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self.get_api().keys_key_id_decrypt_post(
                path_params=path_params, body=body
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. invalid encryption mode",
                    404: f"Key {key_id} not found",
                },
            )
        return response.body.decrypted

    def sign(
        self,
        key_id: str,
        data: str,
        mode: Literal[
            "PKCS1",
            "PSS_MD5",
            "PSS_SHA1",
            "PSS_SHA224",
            "PSS_SHA256",
            "PSS_SHA384",
            "PSS_SHA512",
            "EdDSA",
            "ECDSA",
        ],
    ) -> str:
        from .client.components.schema.sign_request_data import SignRequestDataDict
        from .client.paths.keys_key_id_sign.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = SignRequestDataDict(message=data, mode=mode)
        try:
            response = self.get_api().keys_key_id_sign_post(
                path_params=path_params, body=body
            )
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. invalid sign mode",
                    404: f"Key {key_id} not found",
                },
            )
        return response.body.signature


@contextlib.contextmanager
def connect(
    host: str,
    version: str,
    username: str,
    password: str,
    verify_tls: bool = True,
) -> Iterator[NetHSM]:
    nethsm = NetHSM(host, version, username, password, verify_tls)
    try:
        yield nethsm
    finally:
        nethsm.close()
