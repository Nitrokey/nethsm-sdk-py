import datetime
import ipaddress
import secrets
import time
from dataclasses import dataclass
from tempfile import NamedTemporaryFile

import pytest
from conftest import Constants as C
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from utilities import Container, Version, lock, self_sign_csr, unlock

import nethsm as nethsm_module
from nethsm import Authentication, NetHSM, NetHSMRequestError, RequestErrorType, State, TlsKeyType

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


def _generate_cert(
    *,
    subject_key: ec.EllipticCurvePublicKey,
    issuer_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    issuer_cert: x509.Certificate | None = None,
) -> x509.Certificate:
    if issuer_cert is not None:
        assert issuer_cert.public_key() == issuer_key.public_key()

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

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    path_length = None
    if issuer_cert is not None:
        path_length = 0

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.public_key(subject_key)
    if issuer_cert is not None:
        builder = builder.issuer_name(issuer_cert.subject)
    else:
        builder = builder.issuer_name(name)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=1))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length), critical=True
    )
    builder = builder.add_extension(key_usage, critical=True)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key), critical=False
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _generate_ca_cert(*, ca_key: ec.EllipticCurvePrivateKey, id: str) -> x509.Certificate:
    common_name = f"NetHSM Test CA {id}"
    return _generate_cert(
        issuer_key=ca_key, subject_key=ca_key.public_key(), common_name=common_name
    )


def _generate_int_cert(
    *,
    ca_key: ec.EllipticCurvePrivateKey,
    int_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    id: str,
) -> x509.Certificate:
    common_name = f"NetHSM Intermediate CA {id}"
    return _generate_cert(
        issuer_key=ca_key,
        subject_key=int_key.public_key(),
        common_name=common_name,
        issuer_cert=ca_cert,
    )


@dataclass
class CA:
    """
    CA implementation based on the cryptography documentation:
    https://cryptography.io/en/latest/x509/tutorial/#creating-a-ca-hierarchy
    """

    ca_key: ec.EllipticCurvePrivateKey
    ca_cert: x509.Certificate
    ca_id: str
    int_key: ec.EllipticCurvePrivateKey
    int_cert: x509.Certificate
    int_id: str

    @staticmethod
    def generate() -> "CA":
        ca_key = ec.generate_private_key(ec.SECP256R1())
        int_key = ec.generate_private_key(ec.SECP256R1())
        ca_id = secrets.token_hex(8)
        int_id = secrets.token_hex(8)

        ca_cert = _generate_ca_cert(ca_key=ca_key, id=ca_id)
        int_cert = _generate_int_cert(ca_key=ca_key, int_key=int_key, ca_cert=ca_cert, id=int_id)

        return CA(
            ca_key=ca_key,
            ca_cert=ca_cert,
            ca_id=ca_id,
            int_key=int_key,
            int_cert=int_cert,
            int_id=int_id,
        )

    @staticmethod
    def cross_sign(a: "CA", b: "CA") -> "CA":
        ca_key = b.ca_key
        ca_id = b.ca_id
        int_key = a.int_key
        int_id = a.int_id

        ca_cert = b.ca_cert
        int_cert = _generate_int_cert(ca_key=ca_key, int_key=int_key, ca_cert=ca_cert, id=int_id)

        return CA(
            ca_key=ca_key,
            ca_cert=ca_cert,
            ca_id=ca_id,
            int_key=int_key,
            int_cert=int_cert,
            int_id=int_id,
        )

    def sign(
        self, csr: x509.CertificateSigningRequest, intermediate: bool = True
    ) -> x509.Certificate:
        if intermediate:
            issuer_cert = self.int_cert
            issuer_key = self.int_key
        else:
            issuer_cert = self.ca_cert
            issuer_key = self.ca_key

        now = datetime.datetime.now(datetime.timezone.utc)
        ip = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
        builder = builder.add_extension(x509.SubjectAlternativeName([ip]), critical=False)
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
                [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        cert = builder.sign(issuer_key, hashes.SHA256())

        # sanity check
        self.verify(cert, intermediate=intermediate)

        return cert

    def verify(self, cert: x509.Certificate, intermediate: bool) -> None:
        ip = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        store = x509.verification.Store([self.ca_cert])
        verifier = x509.verification.PolicyBuilder().store(store).build_server_verifier(ip)
        intermediates = []
        if intermediate:
            intermediates = [self.int_cert]
        verifier.verify(cert, intermediates)


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def test_ca_certs_none(container: Container) -> None:
    nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=None)
    try:
        nethsm.get_state()
        raise AssertionError()
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
            raise AssertionError()
        except NetHSMRequestError as e:
            assert e.type == RequestErrorType.SSL_ERROR
        finally:
            nethsm.close()

        nethsm = NetHSM(C.HOST, verify_tls=False, ca_certs=f.name)
        try:
            nethsm.get_state()
            raise AssertionError()
        except NetHSMRequestError as e:
            assert e.type == RequestErrorType.SSL_ERROR
        finally:
            nethsm.close()


def test_ca_certs_valid(container: Container) -> None:
    with NamedTemporaryFile() as f:
        ca = CA.generate()

        f.write(pem(ca.ca_cert))
        f.seek(0)

        nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=f.name)
        try:
            nethsm.get_state()
            raise AssertionError()
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
            nethsm.set_certificate(pem(cert) + pem(ca.int_cert))
        finally:
            nethsm.close()

        f.write(pem(ca.ca_cert))
        f.seek(0)

        nethsm = NetHSM(C.HOST, verify_tls=True, ca_certs=f.name)
        try:
            assert nethsm.get_state() == State.OPERATIONAL
        finally:
            nethsm.close()

        nethsm = NetHSM(C.HOST, verify_tls=True)
        try:
            nethsm.get_state()
            raise AssertionError()
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


def test_get_config_ntp(nethsm: NetHSM) -> None:
    Version(nethsm).require("NTP configuration", major=5)
    config = nethsm.get_config_ntp()
    assert config.ntp_ip is None
    assert config.nts_name is None


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


def test_set_get_ntp_config(nethsm: NetHSM) -> None:
    Version(nethsm).require("NTP configuration", major=5)

    nethsm.set_ntp_config(ntp_ip="127.0.0.1")
    config = nethsm.get_config_ntp()
    assert config.ntp_ip == "127.0.0.1"
    assert config.nts_name is None

    nethsm.set_ntp_config(nts_name="localhost")
    config = nethsm.get_config_ntp()
    assert config.ntp_ip is None
    assert config.nts_name == "localhost"

    nethsm.set_ntp_config(ntp_ip="127.0.0.1", nts_name="localhost")
    config = nethsm.get_config_ntp()
    assert config.ntp_ip == "127.0.0.1"
    assert config.nts_name == "localhost"

    nethsm.set_ntp_config()
    config = nethsm.get_config_ntp()
    assert config.ntp_ip is None
    assert config.nts_name is None


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

    assert nethsm.get_state() == State.OPERATIONAL
    lock(nethsm)
    assert nethsm.get_state() == State.LOCKED
    unlock(nethsm, C.UNLOCK_PASSPHRASE_CHANGED)
    assert nethsm.get_state() == State.OPERATIONAL

    lock(nethsm)
    assert nethsm.get_state() == State.LOCKED

    with pytest.raises(nethsm_module.NetHSMError, match="Access denied -- wrong unlock passphrase"):
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG)
    assert nethsm.get_state() == State.LOCKED

    time.sleep(1)

    with pytest.raises(nethsm_module.NetHSMError, match="Access denied -- wrong unlock passphrase"):
        nethsm.unlock(C.UNLOCK_PASSPHRASE_WRONG_CASE)
    assert nethsm.get_state() == State.LOCKED

    time.sleep(1)

    unlock(nethsm, C.UNLOCK_PASSPHRASE_CHANGED)
    assert nethsm.get_state() == State.OPERATIONAL


def test_cluster_generate_key(nethsm: NetHSM) -> None:
    Version(nethsm).require("clustering", major=5, minor=1)

    old_key_pem = nethsm.get_cluster_public_key()
    old_key = serialization.load_pem_public_key(old_key_pem.encode())

    nethsm.generate_cluster_key(TlsKeyType.RSA, 4096)

    new_key_pem = nethsm.get_cluster_public_key()
    new_key = serialization.load_pem_public_key(new_key_pem.encode())

    assert new_key != old_key
    assert isinstance(new_key, rsa.RSAPublicKey)
    assert new_key.key_size == 4096


def test_cluster_ca_certificate(nethsm: NetHSM) -> None:
    Version(nethsm).require("clustering", major=5, minor=1)

    with pytest.raises(nethsm_module.NetHSMError, match="404: Not Found"):
        nethsm.get_cluster_ca_certificate()

    ca = CA.generate()

    public_key_pem = nethsm.get_cluster_public_key()
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    csr_pem = nethsm.cluster_csr(
        country=C.COUNTRY,
        state_or_province=C.STATE_OR_PROVINCE,
        locality=C.LOCALITY,
        organization=C.ORGANIZATION,
        organizational_unit=C.ORGANIZATIONAL_UNIT,
        common_name=C.COMMON_NAME,
        email_address=C.EMAIL_ADDRESS,
    )
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.public_key() == public_key
    cert_pem = pem(ca.sign(csr, intermediate=False))
    nethsm.set_cluster_certificate(cert_pem)

    nethsm.set_cluster_ca_certificate(pem(ca.ca_cert))

    ca_cert_pem = nethsm.get_cluster_ca_certificate()
    assert ca_cert_pem == pem(ca.ca_cert).decode("utf-8")

    # Test CA rotation. For this we need to use a shared intermediate certificate (same private key
    # and subject) with both the old and new CA.

    cert = ca.sign(csr, intermediate=True)
    nethsm.set_cluster_certificate(pem(cert) + pem(ca.int_cert))

    new_ca = CA.generate()
    cross_sign_ca = CA.cross_sign(ca, new_ca)

    with pytest.raises(
        nethsm_module.NetHSMError, match="the installed TLS cert is not signed by this CA"
    ):
        nethsm.set_cluster_ca_certificate(pem(cross_sign_ca.ca_cert))

    new_cert = cross_sign_ca.sign(csr, intermediate=False)
    with pytest.raises(
        nethsm_module.NetHSMError,
        match="the cluster CA is set, and the given cert is not signed by it",
    ):
        nethsm.set_cluster_certificate(pem(new_cert))

    ca.verify(cert, intermediate=True)
    cross_sign_ca.verify(cert, intermediate=True)

    nethsm.set_cluster_certificate(pem(cert) + pem(ca.int_cert) + pem(cross_sign_ca.int_cert))
    nethsm.set_cluster_ca_certificate(pem(new_ca.ca_cert))

    new_cert = new_ca.sign(csr, intermediate=True)
    nethsm.set_cluster_certificate(pem(new_cert) + pem(new_ca.int_cert))
