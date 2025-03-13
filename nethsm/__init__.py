# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
"""Python Library to manage NetHSM(s)."""

__version__ = "1.3.0"

import binascii
import contextlib
import enum
import json
import string
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BufferedReader, FileIO
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterator,
    Mapping,
    NoReturn,
    Optional,
    Union,
)
from urllib.parse import urlencode

import urllib3
from urllib3 import HTTPResponse, _collections

# Avoid direct imports from .client at runtime to reduce the module load time
if TYPE_CHECKING:
    from .client import ApiException
    from .client.apis.tags.default_api import DefaultApi


Bytes = Union[BufferedReader, FileIO, bytes]


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

    @staticmethod
    def from_string(s: str) -> "UnattendedBootStatus":
        for status in UnattendedBootStatus:
            if status.value == s:
                return status
        raise ValueError(f"Unsupported unattended boot status {s}")


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

    @staticmethod
    def from_string(s: str) -> "KeyMechanism":
        for key_mechanism in KeyMechanism:
            if key_mechanism.value == s:
                return key_mechanism
        raise ValueError(f"Unsupported key mechanism {s}")


class EncryptMode(enum.Enum):
    AES_CBC = "AES_CBC"

    @staticmethod
    def from_string(s: str) -> "EncryptMode":
        for mode in EncryptMode:
            if mode.value == s:
                return mode
        raise ValueError(f"Unsupported encrypt mode {s}")


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

    @staticmethod
    def from_string(s: str) -> "DecryptMode":
        for mode in DecryptMode:
            if mode.value == s:
                return mode
        raise ValueError(f"Unsupported decrypt mode {s}")


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

    @staticmethod
    def from_string(s: str) -> "SignMode":
        for mode in SignMode:
            if mode.value == s:
                return mode
        raise ValueError(f"Unsupported sign mode {s}")


class TlsKeyType(enum.Enum):
    RSA = "RSA"
    CURVE25519 = "Curve25519"
    EC_P224 = "EC_P224"
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"
    EC_P521 = "EC_P521"

    @staticmethod
    def from_string(s: str) -> "TlsKeyType":
        for key_type in TlsKeyType:
            if key_type.value == s:
                return key_type
        raise ValueError(f"Unsupported TLS key type {s}")


@dataclass
class Base64:
    data: str

    def decode(self) -> bytes:
        return b64decode(self.data)

    @classmethod
    def from_encoded(
        cls, data: Union[bytes, str], ignore_whitespace: bool = False
    ) -> "Base64":
        """
        >>> Base64.from_encoded("dGVzdAo=")
        Base64(data='dGVzdAo=')
        >>> Base64.from_encoded(b"dGVzdAo=")
        Base64(data='dGVzdAo=')
        >>> Base64.from_encoded("dGV zdAo=")
        Traceback (most recent call last):
            ...
        ValueError: Invalid base64 data: Non-base64 digit found: dGV zdAo=
        >>> Base64.from_encoded(b"dGV zdAo=")
        Traceback (most recent call last):
            ...
        ValueError: Invalid base64 data: Non-base64 digit found: dGV zdAo=
        >>> Base64.from_encoded("dGV zdAo=", ignore_whitespace=True)
        Base64(data='dGVzdAo=')
        >>> Base64.from_encoded(b"dGV zdAo=", ignore_whitespace=True)
        Base64(data='dGVzdAo=')
        """
        if ignore_whitespace:
            if isinstance(data, bytes):
                data = data.translate(None, delete=string.whitespace.encode())
            else:
                data = data.translate(str.maketrans("", "", string.whitespace))

        try:
            b64decode(data, validate=True)
        except binascii.Error as e:
            if isinstance(data, bytes):
                data = data.decode(errors="replace")
            raise ValueError(f"Invalid base64 data: {e}: {data}") from None

        if isinstance(data, bytes):
            data = data.decode()
        return cls(data=data)

    @classmethod
    def encode(cls, data: bytes) -> "Base64":
        return cls(data=b64encode(data).decode())


@dataclass
class Authentication:
    username: str
    password: str


@dataclass
class Info:
    vendor: str
    product: str


@dataclass
class Tpm:
    attestation_keys: Dict[str, Any]
    platform_configuration_registers: Dict[str, Any]


@dataclass
class SystemInfo:
    firmware_version: str
    software_version: str
    hardware_version: str
    build_tag: str
    tpm: Tpm


@dataclass
class User:
    user_id: str
    real_name: str
    role: Role


@dataclass
class RsaPublicKey:
    modulus: Base64
    public_exponent: Base64


@dataclass
class EcPublicKey:
    data: Base64


PublicKey = Union[RsaPublicKey, EcPublicKey, None]


@dataclass
class RsaPrivateKey:
    prime_p: Base64
    prime_q: Base64
    public_exponent: Base64


@dataclass
class GenericPrivateKey:
    data: Base64


PrivateKey = Union[RsaPrivateKey, GenericPrivateKey]


@dataclass
class Key:
    key_id: str
    mechanisms: list[KeyMechanism]
    type: KeyType
    operations: int
    tags: list[str]
    public_key: PublicKey


@dataclass
class EncryptionResult:
    encrypted: Base64
    iv: Base64


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
) -> NoReturn:
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
) -> NoReturn:
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
        auth: Optional[Authentication] = None,
        verify_tls: bool = True,
    ) -> None:
        from .client import ApiClient, ApiConfiguration
        from .client.components.security_schemes import security_scheme_basic
        from .client.configurations.api_configuration import (
            SecuritySchemeInfo,
            ServerInfo,
        )
        from .client.servers.server_0 import Server0, VariablesDict, Version

        version = Version.default

        self.host = host
        self.version = version
        self.auth = auth

        security_info = None
        if auth:
            security_info = SecuritySchemeInfo(
                {
                    "basic": security_scheme_basic.Basic(
                        user_id=auth.username,
                        password=auth.password,
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

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, str]] = None,
        data: Optional[Bytes] = None,
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

        # basic auth from self.auth
        if self.auth:
            headers[
                "Authorization"
            ] = f"Basic {b64encode(f'{self.auth.username}:{self.auth.password}'.encode('latin-1')).decode()}"

        body: Union[str, bytes, None] = None
        if data:
            if isinstance(data, bytes):
                body = data
            else:
                body = data.read()
        elif json_obj:
            encoder = json.JSONEncoder()
            body = encoder.encode(json_obj)

        response = self._get_api().api_client.rest_client.request(
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

    def _get_create_resource_id(self, response: HTTPResponse) -> str:
        # Endpoints that return CreateResourceId cannot be deserialized because
        # they also set a header which our generator does not support.  We need
        # to deserialize them manually.
        data = response.json()
        assert "id" in data
        value = data["id"]
        assert isinstance(value, str)
        return value

    def _get_api(self) -> "DefaultApi":
        from .client.apis.tags.default_api import DefaultApi

        return DefaultApi(self.client)

    def unlock(self, passphrase: str) -> None:
        from .client.components.schema.unlock_request_data import UnlockRequestDataDict

        request_body = UnlockRequestDataDict(
            passphrase=passphrase,
        )
        try:
            self._get_api().unlock_post(request_body)
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
            self._get_api().lock_post()
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
        system_time: Optional[Union[str, datetime]] = None,
    ) -> None:
        from .client.components.schema.provision_request_data import (
            ProvisionRequestDataDict,
        )

        if system_time is None:
            system_time = datetime.now(timezone.utc)

        request_body = ProvisionRequestDataDict(
            unlockPassphrase=unlock_passphrase,
            adminPassphrase=admin_passphrase,
            systemTime=system_time,
        )
        try:
            self._get_api().provision_post(request_body)
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
            response = self._get_api().users_get()
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
            response = self._get_api().users_user_id_get(path_params=path_params)
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
        role: Role,
        passphrase: str,
        user_id: Optional[str] = None,
        namespace: Optional[str] = None,
    ) -> str:
        from .client.components.schema.user_post_data import UserPostDataDict

        if namespace:
            if user_id:
                user_id = f"{namespace}~{user_id}"
            else:
                namespace = namespace + "~"

        body = UserPostDataDict(
            realName=real_name,
            role=role.value,
            passphrase=passphrase,
        )
        try:
            if user_id:
                from .client.paths.users_user_id.put.path_parameters import (
                    PathParametersDict as PutParameters,
                )

                put_path_params = PutParameters(UserID=user_id)
                self._get_api().users_user_id_put(
                    path_params=put_path_params, body=body
                )
            elif namespace:
                from .client.paths.users_user_id.post.path_parameters import (
                    PathParametersDict as PostParameters,
                )

                post_path_params = PostParameters(UserID=namespace)
                response = self._get_api().users_user_id_post(
                    path_params=post_path_params, body=body, skip_deserialization=True
                )
                user_id = self._get_create_resource_id(response.response)
            else:
                response = self._get_api().users_post(
                    body=body, skip_deserialization=True
                )
                user_id = self._get_create_resource_id(response.response)
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
        return user_id

    def delete_user(self, user_id: str) -> None:
        from .client.paths.users_user_id.delete.path_parameters import (
            PathParametersDict,
        )

        try:
            path_params = PathParametersDict(UserID=user_id)
            self._get_api().users_user_id_delete(path_params=path_params)
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
            self._get_api().users_user_id_passphrase_post(
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

    def list_namespaces(self) -> list[str]:
        try:
            response = self._get_api().namespaces_get()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )
        return [item.id for item in response.body]

    def add_namespace(self, namespace: str) -> None:
        from .client.paths.namespaces_namespace_id.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(NamespaceID=namespace)
        try:
            self._get_api().namespaces_namespace_id_put(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def delete_namespace(self, namespace: str) -> None:
        from .client.paths.namespaces_namespace_id.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(NamespaceID=namespace)
        try:
            self._get_api().namespaces_namespace_id_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def list_operator_tags(self, user_id: str) -> list[str]:
        from .client.paths.users_user_id_tags.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id)
        try:
            response = self._get_api().users_user_id_tags_get(path_params=path_params)
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
            self._get_api().users_user_id_tags_tag_put(path_params=path_params)
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
            self._get_api().users_user_id_tags_tag_delete(path_params=path_params)
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
            self._get_api().keys_key_id_restrictions_tags_tag_put(
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
            self._get_api().keys_key_id_restrictions_tags_tag_delete(
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

    def get_info(self) -> Info:
        try:
            response = self._get_api().info_get()
        except Exception as e:
            _handle_exception(e)
        return Info(vendor=response.body.vendor, product=response.body.product)

    def get_state(self) -> State:
        try:
            response = self._get_api().health_state_get()
        except Exception as e:
            _handle_exception(e)
        return State.from_string(response.body.state)

    def get_random_data(self, n: int) -> Base64:
        from .client.components.schema.random_request_data import RandomRequestDataDict

        body = RandomRequestDataDict(length=n)
        try:
            response = self._get_api().random_post(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Invalid length. Must be between 1 and 1024",
                },
            )
        return Base64.from_encoded(response.body.random)

    def get_metrics(self) -> Mapping[str, Any]:
        try:
            response = self._get_api().metrics_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.METRICS])
        return response.body

    def list_keys(self, filter: Optional[str] = None) -> list[str]:
        from .client.paths.keys.get.query_parameters import QueryParametersDict

        try:
            if filter:
                query_params = QueryParametersDict(filter=filter)
                response = self._get_api().keys_get(query_params=query_params)
            else:
                response = self._get_api().keys_get()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
            )
        return [item.id for item in response.body]

    def get_key(self, key_id: str) -> Key:
        from .client.paths.keys_key_id.get.path_parameters import PathParametersDict
        from .client.schemas import Unset

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self._get_api().keys_key_id_get(path_params=path_params)
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

        mechanisms = [
            KeyMechanism.from_string(mechanism) for mechanism in key.mechanisms
        ]
        tags = []
        if not isinstance(key.restrictions, Unset):
            if not isinstance(key.restrictions.tags, Unset):
                tags = list(key.restrictions.tags)
        key_type = KeyType.from_string(key.type)

        public_key: PublicKey
        if key_type == KeyType.RSA:
            assert not isinstance(key.public, Unset)
            assert isinstance(key.public.data, Unset)
            assert not isinstance(key.public.modulus, Unset)
            assert not isinstance(key.public.publicExponent, Unset)
            public_key = RsaPublicKey(
                modulus=Base64.from_encoded(key.public.modulus),
                public_exponent=Base64.from_encoded(key.public.publicExponent),
            )
        elif key_type == KeyType.GENERIC:
            if not isinstance(key.public, Unset):
                assert isinstance(key.public.data, Unset)
                assert isinstance(key.public.modulus, Unset)
                assert isinstance(key.public.publicExponent, Unset)
            public_key = None
        else:
            assert not isinstance(key.public, Unset)
            assert not isinstance(key.public.data, Unset)
            assert isinstance(key.public.modulus, Unset)
            assert isinstance(key.public.publicExponent, Unset)
            public_key = EcPublicKey(data=Base64.from_encoded(key.public.data))

        return Key(
            key_id=key_id,
            mechanisms=mechanisms,
            type=key_type,
            operations=key.operations,
            tags=tags,
            public_key=public_key,
        )

    # Get the public key file in PEM format
    def get_key_public_key(self, key_id: str) -> str:
        from .client.paths.keys_key_id_public_pem.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self._get_api().keys_key_id_public_pem_get(
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
        key_id: Optional[str],
        type: KeyType,
        mechanisms: list[KeyMechanism],
        private_key: PrivateKey,
        tags: list[str] = [],
    ) -> str:
        from .client.components.schema.key_mechanisms import KeyMechanismsTupleInput
        from .client.components.schema.key_private_data import KeyPrivateDataDict
        from .client.components.schema.key_restrictions import KeyRestrictionsDict
        from .client.components.schema.private_key import PrivateKeyDict
        from .client.components.schema.tag_list import TagListTuple

        if type == KeyType.RSA:
            assert isinstance(private_key, RsaPrivateKey)
            key_data = KeyPrivateDataDict(
                primeP=private_key.prime_p.data,
                primeQ=private_key.prime_q.data,
                publicExponent=private_key.public_exponent.data,
            )
        else:
            assert isinstance(private_key, GenericPrivateKey)
            key_data = KeyPrivateDataDict(data=private_key.data.data)

        mechanism_tuple: KeyMechanismsTupleInput = [
            mechanism.value for mechanism in mechanisms
        ]

        if tags:
            body = PrivateKeyDict(
                type=type.value,
                mechanisms=mechanism_tuple,
                private=key_data,
                restrictions=KeyRestrictionsDict(
                    tags=TagListTuple([tag for tag in tags])
                ),
            )
        else:
            body = PrivateKeyDict(
                type=type.value,
                mechanisms=mechanism_tuple,
                private=key_data,
            )

        try:
            if key_id:
                from .client.paths.keys_key_id.put.path_parameters import (
                    PathParametersDict,
                )

                path_params = PathParametersDict(KeyID=key_id)
                self._get_api().keys_key_id_put(path_params=path_params, body=body)
            else:
                response = self._get_api().keys_post(
                    body=body, skip_deserialization=True
                )
                key_id = self._get_create_resource_id(response.response)
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

    def add_key_pem(
        self,
        key_id: Optional[str],
        mechanisms: list[KeyMechanism],
        private_key: str,
        tags: list[str] = [],
    ) -> str:
        from .client.components.schema.key_mechanisms import KeyMechanismsTupleInput
        from .client.components.schema.key_restrictions import KeyRestrictionsDict
        from .client.components.schema.private_key_pem import (
            ArgumentsDict,
            PrivateKeyPemDict,
        )
        from .client.components.schema.tag_list import TagListTuple

        mechanism_tuple: KeyMechanismsTupleInput = [
            mechanism.value for mechanism in mechanisms
        ]

        if tags:
            arguments = ArgumentsDict(
                mechanisms=mechanism_tuple,
                restrictions=KeyRestrictionsDict(
                    tags=TagListTuple([tag for tag in tags])
                ),
            )
        else:
            arguments = ArgumentsDict(
                mechanisms=mechanism_tuple,
            )
        body = PrivateKeyPemDict(arguments=arguments, key_file=private_key)

        try:
            if key_id:
                from .client.paths.keys_key_id.put.path_parameters import (
                    PathParametersDict,
                )

                path_params = PathParametersDict(KeyID=key_id)
                self._get_api().keys_key_id_put(
                    path_params=path_params,
                    body=body,
                    content_type="multipart/form-data",
                )
            else:
                response = self._get_api().keys_post(
                    body=body,
                    content_type="multipart/form-data",
                    skip_deserialization=True,
                )
                key_id = self._get_create_resource_id(response.response)
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
            self._get_api().keys_key_id_delete(path_params=path_params)
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
        type: KeyType,
        mechanisms: list[KeyMechanism],
        length: int,
        key_id: Optional[str] = None,
    ) -> str:
        from .client.components.schema.key_generate_request_data import (
            KeyGenerateRequestDataDict,
        )
        from .client.components.schema.key_mechanisms import KeyMechanismsTupleInput

        mechanism_tuple: KeyMechanismsTupleInput = [
            mechanism.value for mechanism in mechanisms
        ]

        if key_id:
            body = KeyGenerateRequestDataDict(
                type=type.value,
                mechanisms=mechanism_tuple,
                length=length,
                id=key_id,
            )
        else:
            body = KeyGenerateRequestDataDict(
                type=type.value,
                mechanisms=mechanism_tuple,
                length=length,
            )
        try:
            response = self._get_api().keys_generate_post(
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
        return self._get_create_resource_id(response.response)

    def get_config_logging(self) -> LoggingConfig:
        try:
            response = self._get_api().config_logging_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return LoggingConfig(
            ip_address=response.body.ipAddress,
            log_level=LogLevel.from_string(response.body.logLevel),
            port=response.body.port,
        )

    def get_config_network(self) -> NetworkConfig:
        try:
            response = self._get_api().config_network_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return NetworkConfig(
            gateway=response.body.gateway,
            ip_address=response.body.ipAddress,
            netmask=response.body.netmask,
        )

    def get_config_time(self) -> datetime:
        try:
            response = self._get_api().config_time_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        # could be replaced with datetime.fromisoformat in Python 3.11 or later
        return datetime.strptime(response.body.time, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )

    def get_config_unattended_boot(self) -> str:
        try:
            response = self._get_api().config_unattended_boot_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body.status

    def get_public_key(self) -> str:
        try:
            response = self._get_api().config_tls_public_pem_get(
                skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def get_certificate(self) -> str:
        try:
            response = self._get_api().config_tls_cert_pem_get(
                skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def get_key_certificate(self, key_id: str) -> bytes:
        try:
            from .client.paths.keys_key_id_cert.get.path_parameters import (
                PathParametersDict,
            )

            path_params = PathParametersDict(KeyID=key_id)

            response = self._get_api().keys_key_id_cert_get(
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

    def set_certificate(self, cert: Bytes) -> None:
        try:
            self._request(
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

    def set_key_certificate(self, key_id: str, cert: Bytes) -> None:
        try:
            from .client.paths.keys_key_id_cert.put.path_parameters import (
                PathParametersDict,
            )

            path_params = PathParametersDict(KeyID=key_id)

            self._get_api().keys_key_id_cert_put(body=cert, path_params=path_params)
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
            self._get_api().keys_key_id_cert_delete(path_params=path_params)
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
            response = self._get_api().config_tls_csr_pem_post(
                body=body, skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def generate_tls_key(
        self,
        type: TlsKeyType,
        length: Optional[int] = None,
    ) -> None:
        from .client.components.schema.tls_key_generate_request_data import (
            TlsKeyGenerateRequestDataDict,
        )
        from .client.schemas import Unset

        body = TlsKeyGenerateRequestDataDict(
            type=type.value,
            length=length if length is not None else Unset(),
        )

        try:
            self._get_api().config_tls_generate_post(body=body)
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
            response = self._get_api().keys_key_id_csr_pem_post(
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
            self._get_api().config_backup_passphrase_put(body=body)
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
            self._get_api().config_unlock_passphrase_put(body=body)
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
        log_level: LogLevel,
    ) -> None:
        from .client.components.schema.logging_config import LoggingConfigDict

        body = LoggingConfigDict(
            ipAddress=ip_address, port=port, logLevel=log_level.value
        )
        try:
            self._get_api().config_logging_put(body=body)
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
            self._get_api().config_network_put(body=body)
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
            self._get_api().config_time_put(body=body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid time format",
                },
            )

    def set_unattended_boot(self, status: UnattendedBootStatus) -> None:
        from .client.components.schema.unattended_boot_config import (
            UnattendedBootConfigDict,
        )

        body = UnattendedBootConfigDict(status=status.value)
        try:
            self._get_api().config_unattended_boot_put(body=body)
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
            response = self._get_api().system_info_get()
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
            tpm=Tpm(
                attestation_keys=dict(response.body.akPub),
                platform_configuration_registers=dict(response.body.pcr),
            ),
        )

    def backup(self) -> bytes:
        try:
            response = self._get_api().system_backup_post()
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

    def restore(self, backup: Bytes, passphrase: str, time: Optional[datetime]) -> None:
        try:
            from .client.components.schema.restore_request import (
                ArgumentsDict,
                RestoreRequestDict,
            )

            if not time:
                time = datetime.now(timezone.utc)

            body = RestoreRequestDict(
                arguments=ArgumentsDict(backupPassphrase=passphrase, systemTime=time),
                backup_file=backup,
            )

            if self.auth:
                self._get_api().system_restore_post(body, security_index=1)
            else:
                self._get_api().system_restore_post(body)
        except Exception as e:
            _handle_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Bad request -- backup did not apply",
                },
            )

    def update(self, image: Bytes) -> str:
        try:
            response = self._get_api().system_update_post(body=image)
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
            self._get_api().system_cancel_update_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def commit_update(self) -> None:
        try:
            self._get_api().system_commit_update_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def reboot(self) -> None:
        try:
            self._get_api().system_reboot_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def shutdown(self) -> None:
        try:
            self._get_api().system_shutdown_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def factory_reset(self) -> None:
        try:
            self._get_api().system_factory_reset_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def encrypt(
        self, key_id: str, data: Base64, mode: EncryptMode, iv: Optional[Base64] = None
    ) -> EncryptionResult:
        from .client.components.schema.encrypt_request_data import (
            EncryptRequestDataDict,
        )
        from .client.paths.keys_key_id_encrypt.post.path_parameters import (
            PathParametersDict,
        )
        from .client.schemas import Unset

        path_params = PathParametersDict(KeyID=key_id)
        body = EncryptRequestDataDict(
            message=data.data, mode=mode.value, iv=iv.data if iv else Unset()
        )
        try:
            response = self._get_api().keys_key_id_encrypt_post(
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
        return EncryptionResult(
            encrypted=Base64.from_encoded(response.body.encrypted),
            iv=Base64.from_encoded(response.body.iv),
        )

    def decrypt(
        self,
        key_id: str,
        data: Base64,
        mode: DecryptMode,
        iv: Optional[Base64] = None,
    ) -> Base64:
        from .client.components.schema.decrypt_request_data import (
            DecryptRequestDataDict,
        )
        from .client.paths.keys_key_id_decrypt.post.path_parameters import (
            PathParametersDict,
        )
        from .client.schemas import Unset

        body = DecryptRequestDataDict(
            encrypted=data.data, mode=mode.value, iv=iv.data if iv else Unset()
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self._get_api().keys_key_id_decrypt_post(
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
        return Base64.from_encoded(response.body.decrypted)

    def sign(
        self,
        key_id: str,
        data: Base64,
        mode: SignMode,
    ) -> Base64:
        from .client.components.schema.sign_request_data import SignRequestDataDict
        from .client.paths.keys_key_id_sign.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = SignRequestDataDict(message=data.data, mode=mode.value)
        try:
            response = self._get_api().keys_key_id_sign_post(
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
        return Base64.from_encoded(response.body.signature)


@contextlib.contextmanager
def connect(
    host: str,
    auth: Optional[Authentication] = None,
    verify_tls: bool = True,
) -> Iterator[NetHSM]:
    nethsm = NetHSM(host, auth, verify_tls)
    try:
        yield nethsm
    finally:
        nethsm.close()
