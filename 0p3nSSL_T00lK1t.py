#!/usr/bin/env python3
# OpenSSL toolkit v1 - OS-agnostic Python port (native OpenSSL via ssl + cryptography)
# Colors removed. Screen clearing: clear at start of each selected action.
# Updated: modern timezone-aware UTC datetimes + cryptography deprecation fixes + more readable dumps.

import sys
import os
import re
import ipaddress
import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from getpass import getpass
from typing import Optional, Tuple
from urllib.request import Request, urlopen


# ---------------------------
# Screen / UI utilities
# ---------------------------

def clear_screen() -> None:
    """
    Clear terminal reliably across PowerShell/CMD and Bash/Zsh.
    Primary: OS command (cls/clear) to avoid raw ANSI escapes showing up.
    Fallback: ANSI clear only if stdout is a real TTY.
    """
    cmd = "cls" if os.name == "nt" else "clear"
    try:
        rc = os.system(cmd)
        if rc == 0:
            return
    except Exception:
        pass

    # Fallback: ANSI only if TTY
    try:
        if sys.stdout.isatty():
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
    except Exception:
        pass


def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def utc_now() -> datetime:
    # Best practice: timezone-aware UTC datetime
    return datetime.now(timezone.utc)


def fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def list_dir() -> None:
    # Cross-platform listing similar to `ls -l` (functional, not byte-identical)
    try:
        entries = sorted(os.listdir("."))
    except Exception as e:
        print(f"Cannot list directory: {e}")
        return

    print("Directory listing:")
    for name in entries:
        try:
            st = os.stat(name)
            size = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            kind = "d" if os.path.isdir(name) else "-"
            print(f"{kind} {size:>10}  {mtime}  {name}")
        except Exception:
            print(f"? {'':>10}  {'':>19}  {name}")


def prompt(msg: str) -> str:
    try:
        return input(msg)
    except EOFError:
        return ""


def show_banner() -> None:
    print(r"""
-----------------------------------

.d88b.                            8
8P  Y8 88b. .d88b 8d8b. d88b d88b 8
8b  d8 8  8 8.dP  8P Y8  Yb.  Yb. 8
 Y88P  88P   Y88P 8   8 Y88P Y88P 8
       8
88888             8 8    w  w
  8   .d8b. .d8b. 8 8.dP w w8ww
  8   8  .8 8  .8 8 88b  8  8
  8    Y8P   Y8P  8 8 Yb 8  Y8P

--------------------by-Futurisiko--
""")


def show_menu() -> None:
    print("\nMenu :")
    print("\nUtility")
    print("1) Install/Check Python crypto backend (cryptography)")
    print("\nKey Tools")
    print("2) Create a RSA Private Key AES/256 Encrypted (PEM)")
    print("3) Dump Private or Public Key (PEM) Data")
    print("\nCertificate Creation Tools")
    print("4) Create Root Self-Signed Certificate")
    print("5) Create Generic CSR/PKCS#10 Request")
    print("6) Issue Certificate with CSR and Target CA")
    print("7) Create a PKCS#12 with PrivKey,Cert and CertChain")
    print("\nCertificate Dump Tools")
    print("8) Dump Certificate Data Locally")
    print("9) Verify and Dump Certificate Data Online (TLS + optional OCSP)")
    print("10) Verify and Dump CSR/PKCS#10 Data Locally")
    print("11) Verify and Dump PKCS#12 Data Locally")
    print("\n99) Exit")


# ---------------------------
# Crypto backend (cryptography)
# ---------------------------

@dataclass
class Crypto:
    rsa: object
    x509: object
    hashes: object
    serialization: object
    NameOID: object
    ocsp: object
    pkcs12: object
    default_backend: object


def load_crypto() -> Optional[Crypto]:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        from cryptography.x509 import ocsp
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.hazmat.backends import default_backend
        return Crypto(
            rsa=rsa,
            x509=x509,
            hashes=hashes,
            serialization=serialization,
            NameOID=NameOID,
            ocsp=ocsp,
            pkcs12=pkcs12,
            default_backend=default_backend,
        )
    except Exception:
        return None


CRYPTO = load_crypto()


def ensure_crypto() -> bool:
    global CRYPTO
    if CRYPTO is not None:
        print("cryptography backend: OK")
        return True

    print("cryptography not found. Trying to install via pip...")
    try:
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=False)
    except Exception as e:
        print(f"Install attempt failed: {e}")
        return False

    CRYPTO = load_crypto()
    if CRYPTO is None:
        print("cryptography still unavailable. Please install manually.")
        return False

    print("cryptography installed and loaded.")
    return True


# ---------------------------
# File helpers
# ---------------------------

def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


# ---------------------------
# Cert datetime helpers (avoid deprecation warnings)
# ---------------------------

def cert_not_before(cert) -> Optional[datetime]:
    return getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)


def cert_not_after(cert) -> Optional[datetime]:
    return getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)


# ---------------------------
# PEM load helpers
# ---------------------------

def load_private_key_pem(path: str):
    if not ensure_crypto():
        return None
    data = read_file_bytes(path)
    pw = getpass("Private key password (empty if none): ")
    password = pw.encode() if pw else None
    try:
        return CRYPTO.serialization.load_pem_private_key(data, password=password)
    except TypeError:
        return CRYPTO.serialization.load_pem_private_key(data, password=password, backend=CRYPTO.default_backend())
    except Exception as e:
        print(f"Failed to load private key: {e}")
        return None


def load_cert_pem(path: str):
    if not ensure_crypto():
        return None
    data = read_file_bytes(path)
    try:
        return CRYPTO.x509.load_pem_x509_certificate(data)
    except TypeError:
        return CRYPTO.x509.load_pem_x509_certificate(data, backend=CRYPTO.default_backend())
    except Exception as e:
        print(f"Failed to load certificate: {e}")
        return None


def load_csr_pem(path: str):
    if not ensure_crypto():
        return None
    data = read_file_bytes(path)
    try:
        return CRYPTO.x509.load_pem_x509_csr(data)
    except TypeError:
        return CRYPTO.x509.load_pem_x509_csr(data, backend=CRYPTO.default_backend())
    except Exception as e:
        print(f"Failed to load CSR: {e}")
        return None


# ---------------------------
# Parse subjectAltName addext
# ---------------------------

def parse_addext_subject_alt_name(addext: str):
    if not ensure_crypto():
        return None

    addext = addext.strip()
    if not addext:
        return None

    if addext.lower().startswith("subjectaltname="):
        payload = addext.split("=", 1)[1].strip()
    else:
        payload = addext

    items = [x.strip() for x in payload.split(",") if x.strip()]
    if not items:
        return None

    gn = []
    bad = []
    for it in items:
        if ":" not in it:
            bad.append(it)
            continue
        k, v = it.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        try:
            if k == "dns":
                gn.append(CRYPTO.x509.DNSName(v))
            elif k == "ip":
                gn.append(CRYPTO.x509.IPAddress(ipaddress.ip_address(v)))
            elif k in ("email", "emailaddress"):
                gn.append(CRYPTO.x509.RFC822Name(v))
            elif k == "uri":
                gn.append(CRYPTO.x509.UniformResourceIdentifier(v))
            else:
                bad.append(it)
        except Exception:
            bad.append(it)

    if bad:
        print(f"WARNING: skipped invalid SAN items: {', '.join(bad)}")

    if not gn:
        return None

    return CRYPTO.x509.SubjectAlternativeName(gn)


# ---------------------------
# Dump utilities
# ---------------------------

def dump_private_key_text(priv) -> str:
    pub = priv.public_key()
    lines = []
    lines.append("===== PRIVATE KEY =====")
    if hasattr(priv, "key_size"):
        lines.append(f"Key Size: {priv.key_size}")

    try:
        nums = priv.private_numbers()
        pubn = nums.public_numbers
        lines.append("Type: RSA")
        lines.append(f"Public Exponent (e): {pubn.e}")
        lines.append(f"Modulus (n): {pubn.n.bit_length()} bits")
        lines.append(f"Modulus (n) hex: {hex(pubn.n)}")
        lines.append(f"Private Exponent (d): {nums.d.bit_length()} bits")
    except Exception:
        lines.append("Type: (unsupported for detailed dump)")

    pem_pub = pub.public_bytes(
        encoding=CRYPTO.serialization.Encoding.PEM,
        format=CRYPTO.serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode(errors="ignore")
    lines.append("\n===== PUBLIC KEY (PEM) =====\n" + pem_pub.strip())
    return "\n".join(lines) + "\n"


def dump_cert_text(cert) -> str:
    lines = []
    lines.append("===== CERTIFICATE =====\n")
    lines.append("Subject")
    lines.append(f"  {cert.subject.rfc4514_string() or '(empty)'}\n")
    lines.append("Issuer")
    lines.append(f"  {cert.issuer.rfc4514_string() or '(empty)'}\n")

    lines.append("Metadata")
    lines.append(f"  Serial Number : {hex(cert.serial_number)}")
    lines.append(f"  Version       : {getattr(getattr(cert, 'version', None), 'name', 'unknown')}")
    lines.append(f"  Signature Hash: {cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'unknown'}\n")

    lines.append("Validity (UTC)")
    lines.append(f"  Not Before: {fmt_dt(cert_not_before(cert))}")
    lines.append(f"  Not After : {fmt_dt(cert_not_after(cert))}\n")

    lines.append("Extensions")
    if not cert.extensions:
        lines.append("  (none)")
        return "\n".join(lines) + "\n"

    for ext in cert.extensions:
        name = getattr(ext.oid, "_name", None) or ext.oid.dotted_string
        lines.append(f"  - {name} (critical={ext.critical})")
        v = ext.value

        # Human-friendly rendering while keeping full info
        try:
            if hasattr(v, "get_values_for_type") and name.lower().endswith("subject alternative name"):
                dns = v.get_values_for_type(CRYPTO.x509.DNSName)
                ips = v.get_values_for_type(CRYPTO.x509.IPAddress)
                emails = v.get_values_for_type(CRYPTO.x509.RFC822Name)
                uris = v.get_values_for_type(CRYPTO.x509.UniformResourceIdentifier)
                if dns:
                    lines.append(f"      DNS   : {', '.join(dns)}")
                if ips:
                    lines.append(f"      IP    : {', '.join([str(x) for x in ips])}")
                if emails:
                    lines.append(f"      Email : {', '.join(emails)}")
                if uris:
                    lines.append(f"      URI   : {', '.join(uris)}")
                continue

            if isinstance(v, CRYPTO.x509.BasicConstraints):
                lines.append(f"      CA          : {v.ca}")
                lines.append(f"      Path Length : {v.path_length}")
                continue

            if isinstance(v, CRYPTO.x509.KeyUsage):
                lines.append(f"      digital_signature : {v.digital_signature}")
                lines.append(f"      content_commitment: {v.content_commitment}")
                lines.append(f"      key_encipherment  : {v.key_encipherment}")
                lines.append(f"      data_encipherment : {v.data_encipherment}")
                lines.append(f"      key_agreement     : {v.key_agreement}")
                lines.append(f"      key_cert_sign     : {v.key_cert_sign}")
                lines.append(f"      crl_sign          : {v.crl_sign}")
                lines.append(f"      encipher_only     : {v.encipher_only}")
                lines.append(f"      decipher_only     : {v.decipher_only}")
                continue

            if isinstance(v, CRYPTO.x509.ExtendedKeyUsage):
                oids = []
                for oid in v:
                    oids.append(getattr(oid, "_name", None) or oid.dotted_string)
                lines.append(f"      {', '.join(oids) if oids else '(empty)'}")
                continue

            # fallback
            lines.append(f"      {v}")
        except Exception:
            try:
                lines.append(f"      {v}")
            except Exception:
                lines.append("      (unprintable)")

    return "\n".join(lines) + "\n"


def dump_csr_text(csr) -> str:
    lines = []
    lines.append("===== CSR (PKCS#10) =====\n")

    lines.append("Subject")
    lines.append(f"  {csr.subject.rfc4514_string() or '(empty)'}\n")

    lines.append("Public Key")
    try:
        pub = csr.public_key()
        lines.append(f"  Type    : {pub.__class__.__name__}")
        if hasattr(pub, "key_size"):
            lines.append(f"  Key Size: {pub.key_size}")
        try:
            nums = pub.public_numbers()
            if hasattr(nums, "e") and hasattr(nums, "n"):
                lines.append(f"  Exponent (e): {nums.e}")
                lines.append(f"  Modulus  (n): {nums.n.bit_length()} bits")
        except Exception:
            pass
    except Exception as e:
        lines.append(f"  (cannot read public key: {e})")
    lines.append("")

    lines.append("Signature")
    try:
        lines.append(f"  Signature Valid: {csr.is_signature_valid}")
    except Exception:
        lines.append("  Signature Valid: (unknown)")
    lines.append("")

    lines.append("Requested Extensions")
    try:
        exts = csr.extensions
        if not exts:
            lines.append("  (none)")
        else:
            for ext in exts:
                name = getattr(ext.oid, "_name", None) or ext.oid.dotted_string
                lines.append(f"  - {name} (critical={ext.critical})")
                v = ext.value
                try:
                    if hasattr(v, "get_values_for_type") and name.lower().endswith("subject alternative name"):
                        dns = v.get_values_for_type(CRYPTO.x509.DNSName)
                        ips = v.get_values_for_type(CRYPTO.x509.IPAddress)
                        emails = v.get_values_for_type(CRYPTO.x509.RFC822Name)
                        uris = v.get_values_for_type(CRYPTO.x509.UniformResourceIdentifier)
                        if dns:
                            lines.append(f"      DNS   : {', '.join(dns)}")
                        if ips:
                            lines.append(f"      IP    : {', '.join([str(x) for x in ips])}")
                        if emails:
                            lines.append(f"      Email : {', '.join(emails)}")
                        if uris:
                            lines.append(f"      URI   : {', '.join(uris)}")
                    else:
                        lines.append(f"      {v}")
                except Exception:
                    lines.append("      (cannot render extension)")
    except Exception:
        lines.append("  (cannot read extensions)")

    return "\n".join(lines) + "\n"


# ---------------------------
# Online TLS cert fetch (stdlib ssl)
# ---------------------------

def fetch_server_leaf_cert_der(host: str, port: int, timeout: int = 10) -> bytes:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def extract_aia_uris(cert) -> Tuple[Optional[str], Optional[str]]:
    ocsp_url = None
    issuer_url = None
    try:
        from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for desc in aia:
            method = desc.access_method
            loc = desc.access_location
            if isinstance(loc, CRYPTO.x509.UniformResourceIdentifier):
                if method == AuthorityInformationAccessOID.OCSP and ocsp_url is None:
                    ocsp_url = loc.value
                if method == AuthorityInformationAccessOID.CA_ISSUERS and issuer_url is None:
                    issuer_url = loc.value
    except Exception:
        pass
    return ocsp_url, issuer_url


def http_post(url: str, body: bytes, content_type: str) -> bytes:
    req = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": "Python"},
    )
    with urlopen(req, timeout=20) as r:
        return r.read()


def http_get(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "Python"})
    with urlopen(req, timeout=20) as r:
        return r.read()


def do_ocsp_query(leaf_cert, issuer_cert, ocsp_url: str) -> str:
    # Local helper: avoid touching deprecated naive-datetime properties unless we suppress warnings
    try:
        from cryptography.utils import CryptographyDeprecationWarning  # type: ignore
    except Exception:  # pragma: no cover
        class CryptographyDeprecationWarning(Warning):  # fallback
            pass

    def ocsp_dt(obj, utc_attr: str, legacy_attr: str) -> Optional[datetime]:
        if hasattr(obj, utc_attr):
            try:
                return getattr(obj, utc_attr)
            except Exception:
                return None
        # Older cryptography: legacy attrs may exist but warn -> suppress only here
        if hasattr(obj, legacy_attr):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=CryptographyDeprecationWarning)
                try:
                    return getattr(obj, legacy_attr)
                except Exception:
                    return None
        return None

    builder = CRYPTO.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, issuer_cert, CRYPTO.hashes.SHA1())
    req = builder.build()
    req_bytes = req.public_bytes(CRYPTO.serialization.Encoding.DER)

    try:
        resp_bytes = http_post(ocsp_url, req_bytes, "application/ocsp-request")
        ocsp_resp = CRYPTO.ocsp.load_der_ocsp_response(resp_bytes)
    except Exception as e:
        return f"OCSP query failed: {e}\n"

    lines = []
    lines.append("===== OCSP RESPONSE =====")
    try:
        lines.append(f"  Response Status: {ocsp_resp.response_status}")
    except Exception:
        pass

    if ocsp_resp.response_status != CRYPTO.ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "\n".join(lines) + "\n"

    try:
        lines.append(f"  Certificate Status: {ocsp_resp.certificate_status}")

        this_u = ocsp_dt(ocsp_resp, "this_update_utc", "this_update")
        next_u = ocsp_dt(ocsp_resp, "next_update_utc", "next_update")
        rev_t = ocsp_dt(ocsp_resp, "revocation_time_utc", "revocation_time")

        lines.append(f"  This Update (UTC): {fmt_dt(this_u)}")
        lines.append(f"  Next Update (UTC): {fmt_dt(next_u)}")
        lines.append(f"  Revocation Time  : {fmt_dt(rev_t)}")
        lines.append(f"  Revocation Reason: {ocsp_resp.revocation_reason}")
    except Exception:
        pass

    return "\n".join(lines) + "\n"


# ---------------------------
# Option handlers
# (screen clear happens in router, before calling these)
# ---------------------------

def opt_install_check():
    print("\nINSTALL/CHECK PYTHON CRYPTO BACKEND\n")
    ensure_crypto()


def opt_create_rsa_privkey():
    print("\nCREATING PRIVATE RSA ENCRYPTED KEY\n")
    if not ensure_crypto():
        return

    filename = f"priv_key_{ts()}.pem"
    print("1) RSA 2048 (standard)")
    print("2) RSA 4096 (root)\n")
    ch = prompt("").strip()

    bits = 2048 if ch == "1" else 4096 if ch == "2" else None
    if bits is None:
        return

    pw1 = getpass("Encryption password (AES-256) : ")
    if not pw1:
        print("Empty password not allowed for encrypted key.")
        return
    pw2 = getpass("Confirm password : ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return

    priv = CRYPTO.rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = priv.private_bytes(
        encoding=CRYPTO.serialization.Encoding.PEM,
        format=CRYPTO.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=CRYPTO.serialization.BestAvailableEncryption(pw1.encode()),
    )
    write_file_bytes(filename, pem)
    print(f"\nKey generated --> {filename}")


def opt_dump_key():
    print("\nDUMP KEY DATA\n")
    if not ensure_crypto():
        return

    list_dir()
    print(" ")
    varprivpem = prompt("Private Key PEM file : ").strip()
    if not varprivpem:
        return

    print("\n1) Dump Public Key")
    print("2) Dump Private Key (CONFIDENTIAL DATA)\n")
    ch = prompt("").strip()
    print(" ")

    priv = load_private_key_pem(varprivpem)
    if priv is None:
        return

    if ch == "1":
        pub = priv.public_key()
        pem_pub = pub.public_bytes(
            encoding=CRYPTO.serialization.Encoding.PEM,
            format=CRYPTO.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print(pem_pub.decode(errors="ignore"))
    elif ch == "2":
        print(dump_private_key_text(priv))


def opt_create_root_selfsigned():
    print("\nCREATE ROOT SELF-SIGNED CERTIFICATE/CA\n")
    if not ensure_crypto():
        return

    out_name = f"root_cert_selfsigned_{ts()}.pem"
    list_dir()
    print(" ")

    key_path = prompt("Private Key file (better to use RSA 4096): ").strip()
    cn = prompt("Common Name (e.g. Lab Root CA) : ").strip()
    org = prompt("Organization (e.g. Lab CA) : ").strip()
    st = prompt("Country (2-letter code, e.g. US/IT) : ").strip()
    days_s = prompt("Days of Validity (e.g. 365): ").strip()
    try:
        days = int(days_s)
    except Exception:
        return

    priv = load_private_key_pem(key_path)
    if priv is None:
        return

    name = CRYPTO.x509.Name([
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COUNTRY_NAME, st),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.ORGANIZATION_NAME, org),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COMMON_NAME, cn),
    ])

    now = utc_now()
    builder = CRYPTO.x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.public_key(priv.public_key())
    builder = builder.serial_number(CRYPTO.x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(minutes=1))
    builder = builder.not_valid_after(now + timedelta(days=days))

    builder = builder.add_extension(CRYPTO.x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(
        CRYPTO.x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(CRYPTO.x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)

    cert = builder.sign(private_key=priv, algorithm=CRYPTO.hashes.SHA256())
    write_file_bytes(out_name, cert.public_bytes(CRYPTO.serialization.Encoding.PEM))
    print(f"\nRoot Cert Self-Signed generated --> {out_name}")


def opt_create_csr():
    print("\nCREATING CSR/PKCS#10\n")
    if not ensure_crypto():
        return

    reqname = f"csr_request_{ts()}.csr"
    list_dir()
    print(" ")

    priv_path = prompt("Private Key file : ").strip()
    cn = prompt("Common Name (e.g. www.example.com) : ").strip()
    org = prompt("Organization (e.g. Example) : ").strip()
    st = prompt("Country (2-letter code, e.g. US/IT) : ").strip()
    print("Additional Text")
    print("e.g. subjectAltName=DNS:www.example.local,DNS:example.local,IP:10.0.0.1,email:admin@example.com,URI:https://example.com")
    addtext = prompt("").strip()

    priv = load_private_key_pem(priv_path)
    if priv is None:
        return

    subject = CRYPTO.x509.Name([
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COUNTRY_NAME, st),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.ORGANIZATION_NAME, org),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COMMON_NAME, cn),
    ])

    builder = CRYPTO.x509.CertificateSigningRequestBuilder().subject_name(subject)

    san = parse_addext_subject_alt_name(addtext)
    if san is not None:
        builder = builder.add_extension(san, critical=False)

    csr = builder.sign(priv, CRYPTO.hashes.SHA256())
    write_file_bytes(reqname, csr.public_bytes(CRYPTO.serialization.Encoding.PEM))
    print(f"\nRequest generated --> {reqname}")


def opt_issue_cert():
    print("\nISSUE CERTIFICATE WITH CSR AND LOCAL/TARGET CA\n")
    if not ensure_crypto():
        return

    list_dir()
    print(" ")
    issued = f"signed_issued_cert_{ts()}.pem"
    csr_path = prompt("CSR file : ").strip()
    ca_cert_path = prompt("Root CA Cert file : ").strip()
    ca_key_path = prompt("Root CA Key file : ").strip()
    days_s = prompt("Days of Validity (e.g. 365): ").strip()
    try:
        days = int(days_s)
    except Exception:
        return

    csr = load_csr_pem(csr_path)
    ca_cert = load_cert_pem(ca_cert_path)
    ca_key = load_private_key_pem(ca_key_path)
    if csr is None or ca_cert is None or ca_key is None:
        return

    now = utc_now()
    builder = CRYPTO.x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(CRYPTO.x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(minutes=1))
    builder = builder.not_valid_after(now + timedelta(days=days))

    # Copy requested extensions (parity with -copy_extensions copyall)
    try:
        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)
    except Exception:
        pass

    # Ensure leaf constraints if missing (no noisy "verification" message)
    try:
        from cryptography.x509.oid import ExtensionOID
        builder.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except Exception:
        builder = builder.add_extension(CRYPTO.x509.BasicConstraints(ca=False, path_length=None), critical=True)

    cert = builder.sign(private_key=ca_key, algorithm=CRYPTO.hashes.SHA256())
    write_file_bytes(issued, cert.public_bytes(CRYPTO.serialization.Encoding.PEM))
    print(f"\nIssued Certificate generated --> {issued}")


def opt_create_pkcs12():
    print("\nCREATE PKCS#12\n")
    if not ensure_crypto():
        return

    list_dir()
    out_name = f"PKCS12_{ts()}.pfx"
    print(" ")
    priv_path = prompt("Client PEM Private Key file : ").strip()
    cert_path = prompt("Client PEM Certificate file : ").strip()
    chain_path = prompt("PEM Certificate Chain file related : ").strip()

    priv = load_private_key_pem(priv_path)
    cert = load_cert_pem(cert_path)
    if priv is None or cert is None:
        return

    chain_certs = []
    if chain_path:
        try:
            bundle = read_file_bytes(chain_path)
            blocks = re.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\r?\n?",
                bundle,
                flags=re.S,
            )
            for b in blocks:
                try:
                    chain_certs.append(CRYPTO.x509.load_pem_x509_certificate(b))
                except TypeError:
                    chain_certs.append(CRYPTO.x509.load_pem_x509_certificate(b, backend=CRYPTO.default_backend()))
                except Exception:
                    pass
        except Exception:
            pass

    pfx_pw = getpass("PKCS#12 export password (empty for none): ")
    enc = CRYPTO.serialization.BestAvailableEncryption(pfx_pw.encode()) if pfx_pw else CRYPTO.serialization.NoEncryption()

    pfx = CRYPTO.pkcs12.serialize_key_and_certificates(
        name=b"tls-cert",
        key=priv,
        cert=cert,
        cas=chain_certs if chain_certs else None,
        encryption_algorithm=enc,
    )
    write_file_bytes(out_name, pfx)
    print(f"\nPKCS#12 generated --> {out_name}")


def opt_dump_cert_local():
    print("\nDUMP CERTIFICATE DATA\n")
    if not ensure_crypto():
        return

    list_dir()
    print(" ")
    cert_path = prompt("Certificate CRT/PEM file : ").strip()
    cert = load_cert_pem(cert_path)
    if cert is None:
        return

    print("\n1) Dump just data/subject/issuer")
    print("2) Dump ALL Certificate Data\n")
    ch = prompt("").strip()
    print(" ")

    if ch == "1":
        print(f"subject={cert.subject.rfc4514_string()}")
        print(f"issuer={cert.issuer.rfc4514_string()}")
        print(f"notBefore(UTC)={fmt_dt(cert_not_before(cert))}")
        print(f"notAfter(UTC)={fmt_dt(cert_not_after(cert))}")
    elif ch == "2":
        print(dump_cert_text(cert))


def opt_dump_cert_online():
    print("\nDUMP ONLINE CERTIFICATE DATA\n")
    if not ensure_crypto():
        return

    host = prompt("Site to be checked (e.g. google.com) : ").strip()
    port_s = prompt("Service port exposed (e.g. 443) : ").strip()
    try:
        port = int(port_s)
    except Exception:
        return
    print(" ")

    try:
        der = fetch_server_leaf_cert_der(host, port)
    except Exception as e:
        print(f"TLS fetch failed: {e}")
        return

    try:
        leaf = CRYPTO.x509.load_der_x509_certificate(der)
    except TypeError:
        leaf = CRYPTO.x509.load_der_x509_certificate(der, backend=CRYPTO.default_backend())

    print(dump_cert_text(leaf))

    savelocal = prompt("Do you want to save it into a file or check it via OCSP ? ( Yes / No ) : ").strip()
    if savelocal.lower() not in ("y", "yes"):
        print("\nOk |m|")
        return

    targetpem = f"Cert_Dumped_{ts()}.pem"
    write_file_bytes(targetpem, leaf.public_bytes(CRYPTO.serialization.Encoding.PEM))
    print(f"\nCertificate saved --> {targetpem}\n")

    checkocsp = prompt("Do you want to check Certificate state via OCSP ? ( Yes / No ) : ").strip()
    if checkocsp.lower() not in ("y", "yes"):
        print("\nOk |m|")
        return

    ocsp_url, issuer_url = extract_aia_uris(leaf)
    if not ocsp_url or not issuer_url:
        print("Could not extract OCSP/CA Issuers URIs from certificate AIA.")
        return

    base = f"Issuer_for_OCSP_query_{ts()}"
    cer_path = f"{base}.cer"
    pem_path = f"{base}.pem"

    try:
        issuer_bytes = http_get(issuer_url)
        write_file_bytes(cer_path, issuer_bytes)
    except Exception as e:
        print(f"Issuer download failed: {e}")
        return

    issuer = None
    try:
        issuer = CRYPTO.x509.load_der_x509_certificate(issuer_bytes)
    except Exception:
        try:
            issuer = CRYPTO.x509.load_pem_x509_certificate(issuer_bytes)
        except Exception:
            issuer = None

    if issuer is None:
        print("Cannot parse issuer certificate.")
        return

    write_file_bytes(pem_path, issuer.public_bytes(CRYPTO.serialization.Encoding.PEM))
    print(f"\nIssuer Certificate CER --> {cer_path}")
    print(f"Issuer Certificate PEM --> {pem_path}\n")

    print(do_ocsp_query(leaf, issuer, ocsp_url))


def opt_verify_csr():
    print("\nCSR VERIFICATION\n")
    if not ensure_crypto():
        return

    list_dir()
    print(" ")
    csr_path = prompt("CSR file : ").strip()
    csr = load_csr_pem(csr_path)
    if csr is None:
        return
    print(" ")

    try:
        ok = csr.is_signature_valid
        print(f"CSR signature valid: {ok}")
    except Exception:
        print("CSR signature validity unknown (backend dependent).")

    print("\nINSPECTING CSR\n")
    print(dump_csr_text(csr))


def opt_dump_pkcs12():
    print("\nDUMP PKCS#12 DATA\n")
    if not ensure_crypto():
        return

    list_dir()
    ts0 = ts()
    extractedcert = f"Extracted_Cert_{ts0}.pem"
    extractedchain = f"Extracted_Chain_{ts0}.pem"
    extractedpriv = f"Extracted_PrivKey_{ts0}.pem"
    print(" ")
    pfx_path = prompt("PKCS#12 PFX file : ").strip()

    print("\n1) General Inspection")
    print("2) Extract Cert PEM and Chain PEM")
    print("3) Extract Priv Key CONFIDENTIAL DATA\n")
    ch = prompt("").strip()
    print(" ")

    try:
        pfx_bytes = read_file_bytes(pfx_path)
    except Exception as e:
        print(f"Cannot read PFX: {e}")
        return

    pw = getpass("PKCS#12 password (empty if none): ")
    password = pw.encode() if pw else None

    try:
        key, cert, cas = CRYPTO.pkcs12.load_key_and_certificates(pfx_bytes, password=password)
    except Exception as e:
        print(f"PKCS#12 parse failed: {e}")
        return

    if ch == "1":
        print("PKCS#12:")
        print(f"  Has private key: {bool(key)}")
        print(f"  Has leaf cert:   {bool(cert)}")
        print(f"  Chain length:    {len(cas) if cas else 0}")
        if cert:
            print("\nLeaf certificate:\n" + dump_cert_text(cert))
    elif ch == "2":
        if cert:
            write_file_bytes(extractedcert, cert.public_bytes(CRYPTO.serialization.Encoding.PEM))
            print(f"\nExtracted Cert PEM file --> {extractedcert}")
        if cas:
            chain_pem = b"".join([c.public_bytes(CRYPTO.serialization.Encoding.PEM) for c in cas])
            write_file_bytes(extractedchain, chain_pem)
            print(f"Extracted Chain PEM file --> {extractedchain}")
    elif ch == "3":
        if key is None:
            print("No private key in PKCS#12.")
            return
        out_pw = getpass("Output private key encryption password (empty for none): ")
        enc = CRYPTO.serialization.BestAvailableEncryption(out_pw.encode()) if out_pw else CRYPTO.serialization.NoEncryption()
        pem = key.private_bytes(
            encoding=CRYPTO.serialization.Encoding.PEM,
            format=CRYPTO.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        write_file_bytes(extractedpriv, pem)
        print(f"\nExtracted Private Key PEM file --> {extractedpriv}")
        print("CONFIDENTIAL DATA")


# ---------------------------
# Main option router
# ---------------------------

def read_option():
    choice = prompt("Enter choice : ").strip()

    if choice == "1":
        clear_screen()
        opt_install_check()
    elif choice == "2":
        clear_screen()
        opt_create_rsa_privkey()
    elif choice == "3":
        clear_screen()
        opt_dump_key()
    elif choice == "4":
        clear_screen()
        opt_create_root_selfsigned()
    elif choice == "5":
        clear_screen()
        opt_create_csr()
    elif choice == "6":
        clear_screen()
        opt_issue_cert()
    elif choice == "7":
        clear_screen()
        opt_create_pkcs12()
    elif choice == "8":
        clear_screen()
        opt_dump_cert_local()
    elif choice == "9":
        clear_screen()
        opt_dump_cert_online()
    elif choice == "10":
        clear_screen()
        opt_verify_csr()
    elif choice == "11":
        clear_screen()
        opt_dump_pkcs12()
    elif choice == "99":
        print("\nHack the Planet |m|\n")
        raise SystemExit(0)
    else:
        clear_screen()
        print("\nInvalid option. Please try again.")


def main():
    while True:
        show_banner()
        show_menu()
        read_option()
        print(" ")


if __name__ == "__main__":
    main()
