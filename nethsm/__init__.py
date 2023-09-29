# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
"""Python Library to manage NetHSM(s)."""

import pathlib
from base64 import b64encode

import urllib3

__version_path__ = pathlib.Path(__file__).parent.resolve().absolute() / "VERSION"
__version__ = open(__version_path__).read().strip()

import contextlib
import enum
import json
import re
from datetime import datetime
from io import BufferedReader
from typing import Any, List, Literal, Optional, Tuple, Union, cast
from urllib.parse import urlencode

from urllib3 import HTTPResponse, _collections
from urllib3._collections import HTTPHeaderDict

from nethsm.client.api_response import ApiResponseWithoutDeserialization
from nethsm.client.configurations.api_configuration import ServerInfo
from nethsm.client.schemas import Unset
from nethsm.client.schemas.original_immutabledict import immutabledict
from nethsm.client.schemas.schemas import OUTPUT_BASE_TYPES

from . import client
from .client import ApiException
from .client.apis.tags.default_api import DefaultApi


class Role(enum.Enum):
    ADMINISTRATOR = "Administrator"
    OPERATOR = "Operator"
    METRICS = "Metrics"
    BACKUP = "Backup"

    @staticmethod
    def from_model(model_role):
        return Role.from_string(model_role.value)

    @staticmethod
    def from_string(s: str):
        for role in Role:
            if role.value == s:
                return role
        raise ValueError(f"Unsupported user role {s}")


class State(enum.Enum):
    UNPROVISIONED = "Unprovisioned"
    LOCKED = "Locked"
    OPERATIONAL = "Operational"

    @staticmethod
    def from_model(model_state):
        return State.from_string(model_state.value)

    @staticmethod
    def from_string(s):
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
    def from_model(model_log_level):
        return LogLevel.from_string(model_log_level.value)

    @staticmethod
    def from_string(s: str):
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
    def from_string(s: str):
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


class SystemInfo:
    def __init__(
        self,
        firmware_version: str,
        software_version: str,
        hardware_version: str,
        build_tag: str,
    ):
        self.firmware_version = firmware_version
        self.software_version = software_version
        self.hardware_version = hardware_version
        self.build_tag = build_tag


class User:
    def __init__(self, user_id: str, real_name: str, role: Role):
        self.user_id = user_id
        self.real_name = real_name
        self.role = role


class Key:
    def __init__(
        self,
        key_id: str,
        mechanisms: list[str],
        type: KeyType,
        operations: int,
        tags: Optional[List[str]],
        modulus: Optional[str],
        public_exponent: Optional[str],
        data: Optional[str],
    ):
        self.key_id = key_id
        self.mechanisms = mechanisms
        self.type = type
        self.operations = operations
        self.tags = tags
        self.modulus = modulus
        self.public_exponent = public_exponent
        self.data = data


def _handle_exception(
    e: Exception,
    messages: dict[int, str] = {},
    roles: list[Role] = [],
    state: Optional[State] = None,
):
    if isinstance(e, ApiException):
        _handle_api_exception(e, messages, roles, state)
    elif isinstance(e, urllib3.exceptions.MaxRetryError):
        if isinstance(e.reason, urllib3.exceptions.SSLError):
            raise NetHSMRequestError(RequestErrorType.SSL_ERROR, e)
        raise NetHSMRequestError(RequestErrorType.OTHER, e)
    else:
        raise e


def _handle_api_exception(
    e: ApiException,
    messages: dict[int, str] = {},
    roles: list[Role] = [],
    state: Optional[State] = None,
):
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
    def __init__(self, message: str):
        super().__init__(message)


class RequestErrorType(enum.Enum):
    SSL_ERROR = "SSL_ERROR"
    OTHER = "OTHER"


class NetHSMRequestError(Exception):
    def __init__(self, type: RequestErrorType, reason: Exception):
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
    ):
        from .client.components.security_schemes import security_scheme_basic
        from .client.configurations.api_configuration import SecuritySchemeInfo
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
        config = client.ApiConfiguration(
            server_info=server_config, security_scheme_info=security_info
        )
        config.verify_ssl = verify_tls
        self.client = client.ApiClient(configuration=config)

        if not verify_tls:
            urllib3.disable_warnings()

    def close(self):
        self.client.close()

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, str]] = None,
        data: Optional[BufferedReader] = None,
        mime_type: Optional[str] = "application/json",
        json_obj: Optional[Any] = None,
    ) -> HTTPResponse:

        url = f"https://{self.host}/api/{self.version}/{endpoint}"

        if params:
            url += "?" + urlencode(params)

        headers = _collections.HTTPHeaderDict()

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
            api_response = ApiResponseWithoutDeserialization(response)
            raise ApiException(
                status=response.status,
                reason=response.reason,
                api_response=api_response,
            )
        return response

    def get_api(self) -> DefaultApi:
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

    def unlock(self, passphrase: str):
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

    def lock(self):
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
    ):
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
            return [str(item["user"]) for item in response.body]
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )
        return []

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

    def delete_user(self, user_id: str):
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

    def set_passphrase(self, user_id: str, passphrase: str):
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

    def list_operator_tags(self, user_id: str):
        from .client.paths.users_user_id_tags.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id)
        try:
            response = self.get_api().users_user_id_tags_get(path_params=path_params)
            return response.body
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )

    def add_operator_tag(self, user_id: str, tag: str):
        from .client.paths.users_user_id_tags_tag.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id, Tag=tag)
        try:
            return self.get_api().users_user_id_tags_tag_put(path_params=path_params)
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

    def delete_operator_tag(self, user_id: str, tag: str):
        from .client.paths.users_user_id_tags_tag.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id, Tag=tag)
        try:
            return self.get_api().users_user_id_tags_tag_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} or tag {tag} not found",
                },
            )

    def add_key_tag(self, key_id: str, tag: str):
        from .client.paths.keys_key_id_restrictions_tags_tag.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id, Tag=tag)
        try:
            return self.get_api().keys_key_id_restrictions_tags_tag_put(
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

    def delete_key_tag(self, key_id: str, tag: str):
        from .client.paths.keys_key_id_restrictions_tags_tag.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id, Tag=tag)
        try:
            return self.get_api().keys_key_id_restrictions_tags_tag_delete(
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
        return (str(response.body["vendor"]), str(response.body["product"]))

    def get_state(self):
        try:
            response = self.get_api().health_state_get()
            return State.from_string(response.body["state"])
        except Exception as e:
            _handle_exception(e)

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
        return str(response.body["random"])

    def get_metrics(self) -> immutabledict[str, OUTPUT_BASE_TYPES]:
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
        return [str(item["key"]) for item in response.body]

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
        mechanisms,
        tags,
        prime_p,
        prime_q,
        public_exponent,
        data,
    ):
        from .client.components.schema.key_private_data import KeyPrivateDataDict
        from .client.components.schema.key_restrictions import KeyRestrictionsDict
        from .client.components.schema.private_key import PrivateKeyDict
        from .client.components.schema.tag_list import TagListTuple

        if type == "RSA":
            key_data = KeyPrivateDataDict(
                primeP=prime_p,
                primeQ=prime_q,
                publicExponent=public_exponent,
            )
        else:
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
                return key_id
            else:
                response = self.get_api().keys_post(
                    body=body,
                    content_type="application/json",
                    skip_deserialization=True,
                )
                return self.get_key_id_from_location(response.response.getheaders())
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

    def delete_key(self, key_id: str):
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
        mechanisms: Tuple[KeyMechanismLiteral],
        length: int,
        key_id: Optional[str] = None,
    ):
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

    def get_config_logging(self):
        try:
            response = self.get_api().config_logging_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body

    def get_config_network(self):
        try:
            response = self.get_api().config_network_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body

    def get_config_time(self):
        try:
            response = self.get_api().config_time_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body.time

    def get_config_unattended_boot(self):
        try:
            response = self.get_api().config_unattended_boot_get()
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.body.status

    def get_public_key(self):
        try:
            response = self.get_api().config_tls_public_pem_get(
                skip_deserialization=True
            )
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def get_certificate(self):
        try:
            response = self.get_api().config_tls_cert_pem_get(skip_deserialization=True)
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])
        return response.response.data.decode("utf-8")

    def get_key_certificate(self, key_id: str):
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
        return response.response.data.decode("utf-8")

    def set_certificate(self, cert: BufferedReader):
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

    def set_key_certificate(self, key_id: str, cert: BufferedReader, mime_type: str):
        try:
            self.request("PUT", f"keys/{key_id}/cert", data=cert, mime_type=mime_type)
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

    def delete_key_certificate(self, key_id: str):
        from .client.paths.keys_key_id_cert.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            return self.get_api().keys_key_id_cert_delete(path_params=path_params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"Key {key_id} not found",
                    409: f"Certificate for key {key_id} not found",
                },
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
    ):
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
            return response.response.data.decode("utf-8")
        except Exception as e:
            _handle_exception(e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR])

    def generate_tls_key(
        self,
        type: Literal["RSA", "Curve25519", "EC_P224", "EC_P256", "EC_P384", "EC_P521"],
        length: Union[int, Unset] = Unset(),
    ):
        from .client.components.schema.tls_key_generate_request_data import (
            TlsKeyGenerateRequestDataDict,
        )

        body = TlsKeyGenerateRequestDataDict(
            type=type,
            length=length,
        )

        try:
            return self.get_api().config_tls_generate_post(body=body)
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
    ):
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
            return response.response.data.decode("utf-8")
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )

    def set_backup_passphrase(self, passphrase: str):
        from .client.components.schema.backup_passphrase_config import (
            BackupPassphraseConfigDict,
        )

        body = BackupPassphraseConfigDict(passphrase=passphrase)
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

    def set_unlock_passphrase(self, passphrase: str):
        from .client.components.schema.unlock_passphrase_config import (
            UnlockPassphraseConfigDict,
        )

        body = UnlockPassphraseConfigDict(passphrase=passphrase)
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
    ):
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

    def set_network_config(self, ip_address: str, netmask: str, gateway: str):
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

    def set_time(self, time: Union[str, datetime]):
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

    def set_unattended_boot(self, status: Literal["on", "off"]):
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

    def get_system_info(self):
        try:
            response = self.get_api().system_info_get()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )
        return SystemInfo(
            firmware_version=response.body["firmwareVersion"],
            software_version=response.body["softwareVersion"],
            hardware_version=response.body["hardwareVersion"],
            build_tag=response.body["softwareBuild"],
        )

    def backup(self):
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

    def restore(self, backup: BufferedReader, passphrase: str, time: datetime):
        try:
            from .client.paths.system_restore.post.query_parameters import (
                QueryParametersDict,
            )

            params = QueryParametersDict(
                backupPassphrase=passphrase, systemTime=time.isoformat()
            )
            self.get_api().system_restore_post(body=backup, query_params=params)
        except Exception as e:
            _handle_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Bad request -- backup did not apply",
                },
            )

    def update(self, image: BufferedReader):
        try:
            # Currently the deserialisation doesn't work because of a bug where the api sends the content-type header twice
            # https://git.nitrokey.com/nitrokey/nethsm/nethsm/-/issues/245

            response = self.get_api().system_update_post(
                body=image, skip_deserialization=True
            )
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
        return json.loads(json_str)["releaseNotes"]

        # # Use this one when the bug is fixed:
        # return response.body.releaseNotes

    def cancel_update(self):
        try:
            self.get_api().system_cancel_update_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def commit_update(self):
        try:
            self.get_api().system_commit_update_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def reboot(self):
        try:
            self.get_api().system_reboot_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def shutdown(self):
        try:
            self.get_api().system_shutdown_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def factory_reset(self):
        try:
            self.get_api().system_factory_reset_post()
        except Exception as e:
            _handle_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def encrypt(self, key_id: str, data: str, mode: Literal["AES_CBC"], iv: str):
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
    ):
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
    ):
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
def connect(host, version, username, password, verify_tls=True):
    nethsm = NetHSM(host, version, username, password, verify_tls)
    try:
        yield nethsm
    finally:
        nethsm.close()
