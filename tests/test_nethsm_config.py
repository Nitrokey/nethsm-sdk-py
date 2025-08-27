import datetime
import ipaddress
import secrets
from tempfile import NamedTemporaryFile

import pytest
from conftest import Constants as C
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from utilities import Container, lock, self_sign_csr, unlock

import nethsm as nethsm_module
from nethsm import (
    Authentication,
    NetHSM,
    NetHSMRequestError,
    RequestErrorType,
    State,
    TlsKeyType,
)

"""########## Preparation for the Tests ##########

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


def get_config_logging(nethsm: NetHSM) -> None:
    data = nethsm.get_config_logging()
    assert data.ip_address == C.IP_ADDRESS_LOGGING
    assert data.port == C.PORT
    assert data.log_level == C.LOG_LEVEL


def get_config_network(nethsm: NetHSM) -> None:
    data = nethsm.get_config_network()
    assert data.ip_address == C.IP_ADDRESS_NETWORK
    assert data.netmask == C.NETMASK
    assert data.gateway == C.GATEWAY


def get_config_time(nethsm: NetHSM) -> None:
    dt_nethsm = nethsm.get_config_time()
    dt_now = datetime.datetime.now(datetime.timezone.utc)

    seconds_diff = (dt_nethsm - dt_now).total_seconds()

    # Magic Constant 2.0
    # Due to network latency and execution time, the time difference may vary.
    # Therefore the time check allows a delta of nearly 2.0 seconds.

    assert abs(seconds_diff) < 2.0


"""##########Start of Tests##########"""


class CA:
    """
    CA implementation based on the cryptography documentation:
    https://cryptography.io/en/latest/x509/tutorial/#creating-a-ca-hierarchy
    """

    def __init__(self) -> None:
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_id = secrets.token_hex(8)

        now = datetime.datetime.now(datetime.timezone.utc)
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )

        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, f"NetHSM Test CA {self.ca_id}"),
            ]
        )
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(name)
        builder = builder.public_key(self.ca_key.public_key())
        builder = builder.issuer_name(name)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(key_usage, critical=True)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
            critical=False,
        )
        self.ca_cert = builder.sign(self.ca_key, hashes.SHA256())

        name = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"NetHSM Intermediate CA {self.ca_id}"
                ),
            ]
        )
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(name)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.public_key(self.int_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        builder = builder.add_extension(key_usage, critical=True)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.int_key.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )
        self.int_cert = builder.sign(self.ca_key, hashes.SHA256())

    def sign(self, csr: x509.CertificateSigningRequest) -> bytes:
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        ip = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(self.int_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
        builder = builder.add_extension(
            x509.SubjectAlternativeName([ip]), critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.int_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )
        cert = builder.sign(self.int_key, hashes.SHA256())

        # sanity check
        store = x509.verification.Store([self.ca_cert])
        verifier = (
            x509.verification.PolicyBuilder().store(store).build_server_verifier(ip)
        )
        verifier.verify(cert, [self.int_cert])

        return cert.public_bytes(
            serialization.Encoding.PEM
        ) + self.int_cert.public_bytes(serialization.Encoding.PEM)

    @property
    def ca_cert_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)


def test_ca_certs_none(container: Container) -> None:
    nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=None)
    try:
        nethsm.get_state()
        assert False
    except NetHSMRequestError as e:
        assert e.type == RequestErrorType.SSL_ERROR
    finally:
        nethsm.close()

    nethsm = NetHSM(C.HOST, verify_tls=False, ca_certs=None)
    try:
        assert nethsm.get_state() == State.UNPROVISIONED
    finally:
        nethsm.close()


def test_ca_certs_empty(container: Container) -> None:
    with NamedTemporaryFile() as f:
        nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=f.name)
        try:
            nethsm.get_state()
            assert False
        except NetHSMRequestError as e:
            assert e.type == RequestErrorType.SSL_ERROR
        finally:
            nethsm.close()

        nethsm = NetHSM(C.HOST, verify_tls=False, ca_certs=f.name)
        try:
            nethsm.get_state()
            assert False
        except NetHSMRequestError as e:
            assert e.type == RequestErrorType.SSL_ERROR
        finally:
            nethsm.close()


def test_ca_certs_valid(container: Container) -> None:
    with NamedTemporaryFile() as f:
        ca = CA()

        f.write(ca.ca_cert_pem)
        f.seek(0)

        nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=f.name)
        try:
            nethsm.get_state()
            assert False
        except NetHSMRequestError as e:
            assert e.type == RequestErrorType.SSL_ERROR
        finally:
            nethsm.close()

        nethsm = NetHSM(C.HOST, verify_tls=False)
        try:
            nethsm.provision("unlockunlock", "adminadmin")
        finally:
            nethsm.close()

        auth = Authentication(username="admin", password="adminadmin")
        nethsm = NetHSM(C.HOST, auth=auth, verify_tls=False)
        try:
            csr_pem = nethsm.csr(
                country=C.COUNTRY,
                state_or_province=C.STATE_OR_PROVINCE,
                locality=C.LOCALITY,
                organization=C.ORGANIZATION,
                organizational_unit=C.ORGANIZATIONAL_UNIT,
                common_name=C.COMMON_NAME,
                email_address=C.EMAIL_ADDRESS,
            )
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            cert = ca.sign(csr)
            nethsm.set_certificate(cert)
        finally:
            nethsm.close()

        f.write(ca.ca_cert_pem)
        f.seek(0)

        nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=f.name)
        try:
            assert nethsm.get_state() == State.OPERATIONAL
        finally:
            nethsm.close()

        nethsm = NetHSM(C.HOST, verify_tls=True)
        try:
            nethsm.get_state()
            assert False
        except NetHSMRequestError as e:
            assert e.type == RequestErrorType.SSL_ERROR
        finally:
            nethsm.close()

        nethsm = NetHSM(C.HOST, auth=auth, verify_tls=True, ca_certs=f.name)
        try:
            nethsm.factory_reset()
        finally:
            nethsm.close()

    container.restart()


def test_csr(nethsm: NetHSM) -> None:
    csr = nethsm.csr(
        country=C.COUNTRY,
        state_or_province=C.STATE_OR_PROVINCE,
        locality=C.LOCALITY,
        organization=C.ORGANIZATION,
        organizational_unit=C.ORGANIZATIONAL_UNIT,
        common_name=C.COMMON_NAME,
        email_address=C.EMAIL_ADDRESS,
    )
    print(csr)


def test_set_certificate(nethsm: NetHSM) -> None:

    csr = nethsm.csr(
        country=C.COUNTRY,
        state_or_province=C.STATE_OR_PROVINCE,
        locality=C.LOCALITY,
        organization=C.ORGANIZATION,
        organizational_unit=C.ORGANIZATIONAL_UNIT,
        common_name=C.COMMON_NAME,
        email_address=C.EMAIL_ADDRESS,
    )
    cert = self_sign_csr(csr)
    nethsm.set_certificate(cert)

    remote_cert = nethsm.get_certificate()
    assert cert.decode("utf-8") == remote_cert


def generate_tls_key(nethsm: NetHSM) -> None:
    nethsm.generate_tls_key(TlsKeyType.RSA, 2048)


def test_get_config_logging(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For logging

    This command requires authentication as a user with the Administrator
    role."""
    get_config_logging(nethsm)


def test_get_config_network(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For network

    This command requires authentication as a user with the Administrator
    role."""
    get_config_logging(nethsm)


def test_get_config_time(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For time

    This command requires authentication as a user with the Administrator
    role."""

    get_config_time(nethsm)


def test_get_config_unattended_boot(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For unattended boot

    This command requires authentication as a user with the Administrator
    role."""
    unattended_boot = nethsm.get_config_unattended_boot()
    assert (
        unattended_boot == C.UNATTENDED_BOOT_OFF.value
        or unattended_boot == C.UNATTENDED_BOOT_ON.value
    )


def test_get_config_get_public_key(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For get public key

    This command requires authentication as a user with the Administrator
    role.
    Todo: More checks"""
    # public_key = nethsm_alt.get_public_key()
    str_begin = nethsm.get_public_key()[:26]
    assert str_begin == "-----BEGIN PUBLIC KEY-----"
    str_end = nethsm.get_public_key()[-25:-1]
    assert str_end == "-----END PUBLIC KEY-----"


def test_get_config_get_certificate(nethsm: NetHSM) -> None:
    """Query the configuration of a NetHSM.

    For get certificate

    This command requires authentication as a user with the Administrator
    role.
    Todo: More checks"""
    # certificate = nethsm_alt.get_certificate()
    str_begin = nethsm.get_certificate()[:27]
    assert str_begin == "-----BEGIN CERTIFICATE-----"
    str_end = nethsm.get_certificate()[-26:-1]
    assert str_end == "-----END CERTIFICATE-----"


def test_set_backup_passphrase(nethsm: NetHSM) -> None:
    """Set the backup passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role. Todo: Later the test would try to do an update with the changed
    passphrase which asserts True and with a wrong passphrase which asserts
    true only if failing. Because this test is dependant of set_backup,
    reset and restore it would be better to write an own module for that with
    a suitable fixture"""
    nethsm.set_backup_passphrase(C.BACKUP_PASSPHRASE_CHANGED)
    nethsm.set_backup_passphrase(
        C.BACKUP_PASSPHRASE, current_passphrase=C.BACKUP_PASSPHRASE_CHANGED
    )


# @pytest.mark.skip(reason="not finished yet")
def test_set_get_logging_config(nethsm: NetHSM) -> None:
    """Set the logging configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    Todo: I don't know which parameters i should set the nethsm to
    Write test which with get_config_logging asserts that given Parameters
    were set"""
    nethsm.set_logging_config(C.IP_ADDRESS_LOGGING, C.PORT, C.LOG_LEVEL)
    get_config_logging(nethsm)


# @pytest.mark.skip(reason="not finished yet")
def test_set_get_network_config(nethsm: NetHSM) -> None:
    """Set the network configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    Todo: I don't know which parameters i should set the nethsm to
    Write test which with get_config_network asserts that given Parameters
    were set"""
    nethsm.set_network_config(C.IP_ADDRESS_NETWORK, C.NETMASK, C.GATEWAY)
    get_config_network(nethsm)


def test_set_get_time(nethsm: NetHSM) -> None:
    """Set the system time of a NetHSM.

    If the time is not given as an argument, the system time of this system
    is used.

    This command requires authentication as a user with the Administrator
    role."""
    time_now = datetime.datetime.now(datetime.timezone.utc)
    nethsm.set_time(time_now)
    get_config_time(nethsm)


def test_set_get_unattended_boot(nethsm: NetHSM) -> None:
    """Set the unattended boot configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    unattended_boot = nethsm.get_config_unattended_boot()
    if unattended_boot == C.UNATTENDED_BOOT_OFF.value:
        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_ON)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_ON.value

        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_OFF)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_OFF.value

    if unattended_boot == C.UNATTENDED_BOOT_ON.value:
        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_OFF)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_OFF.value

        nethsm.set_unattended_boot(C.UNATTENDED_BOOT_ON)
        assert nethsm.get_config_unattended_boot() == C.UNATTENDED_BOOT_ON.value


def test_set_unlock_passphrase_lock_unlock(nethsm: NetHSM) -> None:
    """Set the unlock passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""

    nethsm.set_unlock_passphrase(
        C.UNLOCK_PASSPHRASE_CHANGED, current_passphrase=C.UNLOCK_PASSPHRASE
    )

    lock(nethsm)
    unlock(nethsm, C.UNLOCK_PASSPHRASE_CHANGED)

    with pytest.raises(nethsm_module.NetHSMError):
        lock(nethsm)
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG)

    with pytest.raises(nethsm_module.NetHSMError):
        lock(nethsm)
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG_CASE)
