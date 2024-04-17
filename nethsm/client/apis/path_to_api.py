import typing
import typing_extensions

from nethsm.client.apis.paths.config_backup_passphrase import ConfigBackupPassphrase
from nethsm.client.apis.paths.config_logging import ConfigLogging
from nethsm.client.apis.paths.config_network import ConfigNetwork
from nethsm.client.apis.paths.config_time import ConfigTime
from nethsm.client.apis.paths.config_tls_cert_pem import ConfigTlsCertPem
from nethsm.client.apis.paths.config_tls_csr_pem import ConfigTlsCsrPem
from nethsm.client.apis.paths.config_tls_generate import ConfigTlsGenerate
from nethsm.client.apis.paths.config_tls_public_pem import ConfigTlsPublicPem
from nethsm.client.apis.paths.config_unattended_boot import ConfigUnattendedBoot
from nethsm.client.apis.paths.config_unlock_passphrase import ConfigUnlockPassphrase
from nethsm.client.apis.paths.health_alive import HealthAlive
from nethsm.client.apis.paths.health_ready import HealthReady
from nethsm.client.apis.paths.health_state import HealthState
from nethsm.client.apis.paths.info import Info
from nethsm.client.apis.paths.keys import Keys
from nethsm.client.apis.paths.keys_generate import KeysGenerate
from nethsm.client.apis.paths.keys_key_id import KeysKeyID
from nethsm.client.apis.paths.keys_key_id_cert import KeysKeyIDCert
from nethsm.client.apis.paths.keys_key_id_csr_pem import KeysKeyIDCsrPem
from nethsm.client.apis.paths.keys_key_id_decrypt import KeysKeyIDDecrypt
from nethsm.client.apis.paths.keys_key_id_encrypt import KeysKeyIDEncrypt
from nethsm.client.apis.paths.keys_key_id_public_pem import KeysKeyIDPublicPem
from nethsm.client.apis.paths.keys_key_id_restrictions_tags_tag import KeysKeyIDRestrictionsTagsTag
from nethsm.client.apis.paths.keys_key_id_sign import KeysKeyIDSign
from nethsm.client.apis.paths.lock import Lock
from nethsm.client.apis.paths.metrics import Metrics
from nethsm.client.apis.paths.namespaces import Namespaces
from nethsm.client.apis.paths.namespaces_namespace_id import NamespacesNamespaceID
from nethsm.client.apis.paths.provision import Provision
from nethsm.client.apis.paths.random import Random
from nethsm.client.apis.paths.system_backup import SystemBackup
from nethsm.client.apis.paths.system_cancel_update import SystemCancelUpdate
from nethsm.client.apis.paths.system_commit_update import SystemCommitUpdate
from nethsm.client.apis.paths.system_factory_reset import SystemFactoryReset
from nethsm.client.apis.paths.system_info import SystemInfo
from nethsm.client.apis.paths.system_reboot import SystemReboot
from nethsm.client.apis.paths.system_restore import SystemRestore
from nethsm.client.apis.paths.system_shutdown import SystemShutdown
from nethsm.client.apis.paths.system_update import SystemUpdate
from nethsm.client.apis.paths.unlock import Unlock
from nethsm.client.apis.paths.users import Users
from nethsm.client.apis.paths.users_user_id import UsersUserID
from nethsm.client.apis.paths.users_user_id_passphrase import UsersUserIDPassphrase
from nethsm.client.apis.paths.users_user_id_tags import UsersUserIDTags
from nethsm.client.apis.paths.users_user_id_tags_tag import UsersUserIDTagsTag

PathToApi = typing.TypedDict(
    'PathToApi',
    {
    "/config/backup-passphrase": typing.Type[ConfigBackupPassphrase],
    "/config/logging": typing.Type[ConfigLogging],
    "/config/network": typing.Type[ConfigNetwork],
    "/config/time": typing.Type[ConfigTime],
    "/config/tls/cert.pem": typing.Type[ConfigTlsCertPem],
    "/config/tls/csr.pem": typing.Type[ConfigTlsCsrPem],
    "/config/tls/generate": typing.Type[ConfigTlsGenerate],
    "/config/tls/public.pem": typing.Type[ConfigTlsPublicPem],
    "/config/unattended-boot": typing.Type[ConfigUnattendedBoot],
    "/config/unlock-passphrase": typing.Type[ConfigUnlockPassphrase],
    "/health/alive": typing.Type[HealthAlive],
    "/health/ready": typing.Type[HealthReady],
    "/health/state": typing.Type[HealthState],
    "/info": typing.Type[Info],
    "/keys": typing.Type[Keys],
    "/keys/generate": typing.Type[KeysGenerate],
    "/keys/{KeyID}": typing.Type[KeysKeyID],
    "/keys/{KeyID}/cert": typing.Type[KeysKeyIDCert],
    "/keys/{KeyID}/csr.pem": typing.Type[KeysKeyIDCsrPem],
    "/keys/{KeyID}/decrypt": typing.Type[KeysKeyIDDecrypt],
    "/keys/{KeyID}/encrypt": typing.Type[KeysKeyIDEncrypt],
    "/keys/{KeyID}/public.pem": typing.Type[KeysKeyIDPublicPem],
    "/keys/{KeyID}/restrictions/tags/{Tag}": typing.Type[KeysKeyIDRestrictionsTagsTag],
    "/keys/{KeyID}/sign": typing.Type[KeysKeyIDSign],
    "/lock": typing.Type[Lock],
    "/metrics": typing.Type[Metrics],
    "/namespaces": typing.Type[Namespaces],
    "/namespaces/{NamespaceID}": typing.Type[NamespacesNamespaceID],
    "/provision": typing.Type[Provision],
    "/random": typing.Type[Random],
    "/system/backup": typing.Type[SystemBackup],
    "/system/cancel-update": typing.Type[SystemCancelUpdate],
    "/system/commit-update": typing.Type[SystemCommitUpdate],
    "/system/factory-reset": typing.Type[SystemFactoryReset],
    "/system/info": typing.Type[SystemInfo],
    "/system/reboot": typing.Type[SystemReboot],
    "/system/restore": typing.Type[SystemRestore],
    "/system/shutdown": typing.Type[SystemShutdown],
    "/system/update": typing.Type[SystemUpdate],
    "/unlock": typing.Type[Unlock],
    "/users": typing.Type[Users],
    "/users/{UserID}": typing.Type[UsersUserID],
    "/users/{UserID}/passphrase": typing.Type[UsersUserIDPassphrase],
    "/users/{UserID}/tags": typing.Type[UsersUserIDTags],
    "/users/{UserID}/tags/{Tag}": typing.Type[UsersUserIDTagsTag],
    }
)

path_to_api = PathToApi(
    {
    "/config/backup-passphrase": ConfigBackupPassphrase,
    "/config/logging": ConfigLogging,
    "/config/network": ConfigNetwork,
    "/config/time": ConfigTime,
    "/config/tls/cert.pem": ConfigTlsCertPem,
    "/config/tls/csr.pem": ConfigTlsCsrPem,
    "/config/tls/generate": ConfigTlsGenerate,
    "/config/tls/public.pem": ConfigTlsPublicPem,
    "/config/unattended-boot": ConfigUnattendedBoot,
    "/config/unlock-passphrase": ConfigUnlockPassphrase,
    "/health/alive": HealthAlive,
    "/health/ready": HealthReady,
    "/health/state": HealthState,
    "/info": Info,
    "/keys": Keys,
    "/keys/generate": KeysGenerate,
    "/keys/{KeyID}": KeysKeyID,
    "/keys/{KeyID}/cert": KeysKeyIDCert,
    "/keys/{KeyID}/csr.pem": KeysKeyIDCsrPem,
    "/keys/{KeyID}/decrypt": KeysKeyIDDecrypt,
    "/keys/{KeyID}/encrypt": KeysKeyIDEncrypt,
    "/keys/{KeyID}/public.pem": KeysKeyIDPublicPem,
    "/keys/{KeyID}/restrictions/tags/{Tag}": KeysKeyIDRestrictionsTagsTag,
    "/keys/{KeyID}/sign": KeysKeyIDSign,
    "/lock": Lock,
    "/metrics": Metrics,
    "/namespaces": Namespaces,
    "/namespaces/{NamespaceID}": NamespacesNamespaceID,
    "/provision": Provision,
    "/random": Random,
    "/system/backup": SystemBackup,
    "/system/cancel-update": SystemCancelUpdate,
    "/system/commit-update": SystemCommitUpdate,
    "/system/factory-reset": SystemFactoryReset,
    "/system/info": SystemInfo,
    "/system/reboot": SystemReboot,
    "/system/restore": SystemRestore,
    "/system/shutdown": SystemShutdown,
    "/system/update": SystemUpdate,
    "/unlock": Unlock,
    "/users": Users,
    "/users/{UserID}": UsersUserID,
    "/users/{UserID}/passphrase": UsersUserIDPassphrase,
    "/users/{UserID}/tags": UsersUserIDTags,
    "/users/{UserID}/tags/{Tag}": UsersUserIDTagsTag,
    }
)
