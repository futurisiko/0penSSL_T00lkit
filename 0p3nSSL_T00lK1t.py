#!/usr/bin/env python3
"""
0p3nSSL T00lK1t - Python implementation
by Futurisiko

"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from getpass import getpass
from typing import Optional, Tuple
from urllib.request import Request, urlopen


# ---------------------------
# Terminal UI
# ---------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class C:
    RESET = "\033[0m" if USE_COLOR else ""
    RED = "\033[31m" if USE_COLOR else ""
    GREEN = "\033[32m" if USE_COLOR else ""
    YELLOW = "\033[33m" if USE_COLOR else ""
    BLUE = "\033[34m" if USE_COLOR else ""
    MAGENTA = "\033[35m" if USE_COLOR else ""
    CYAN = "\033[36m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""


def paint(text: str, *styles: str) -> str:
    return "".join(styles) + text + C.RESET if USE_COLOR else text


def ok(msg: str) -> None:
    print(paint(msg, C.GREEN))


def warn(msg: str) -> None:
    print(paint(msg, C.YELLOW))


def err(msg: str) -> None:
    print(paint(msg, C.RED))


def title(msg: str) -> None:
    print(paint(msg, C.BOLD, C.CYAN))


def clear_screen() -> None:
    cmd = "cls" if os.name == "nt" else "clear"
    try:
        rc = os.system(cmd)
        if rc == 0:
            return
    except Exception:
        pass
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def prompt(msg: str) -> str:
    try:
        return input(msg)
    except EOFError:
        return ""


def yes(value: str) -> bool:
    return value.strip().lower() in {"y", "yes"}


def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def list_dir() -> None:
    try:
        entries = sorted(os.listdir("."))
    except Exception as exc:
        err(f"Cannot list directory: {exc}")
        return

    print(paint("Directory listing:", C.DIM))
    for name in entries:
        try:
            st = os.stat(name)
            size = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            kind = "d" if os.path.isdir(name) else "-"
            print(f"{kind} {size:>10} {mtime} {name}")
        except Exception:
            print(f"? {'':>10} {'':>19} {name}")


def show_banner() -> None:
    print(paint(r"""
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
""".strip("\n"), C.MAGENTA))


def show_menu() -> None:
    print(paint("\nMenu:", C.BOLD, C.GREEN))
    print(paint("\nUtility", C.YELLOW))
    print("0) Help / Notes")
    print("1) Install/Check Python crypto backend (cryptography)")
    print(paint("\nKey Tools", C.YELLOW))
    print("2) Create RSA Private Key - encrypted or unencrypted (PEM)")
    print("3) Dump Private or Public Key (PEM) Data")
    print(paint("\nCertificate Creation Tools", C.YELLOW))
    print("4) Create Root Self-Signed Certificate")
    print("5) Create Generic CSR/PKCS#10 Request")
    print("6) Issue Certificate with CSR and Target CA")
    print("7) Create a PKCS#12 with PrivKey, Cert and CertChain")
    print(paint("\nCertificate Dump Tools", C.YELLOW))
    print("8) Dump Certificate Data Locally")
    print("9) Verify and Dump Certificate Data Online (TLS + optional OCSP)")
    print("10) Verify and Dump CSR/PKCS#10 Data Locally")
    print("11) Verify and Dump PKCS#12 Data Locally")
    print(paint("\nValidation Utility", C.YELLOW))
    print("12) DigiCert DCV - DNS TXT precheck")
    print(paint("\n99) Exit", C.YELLOW))


def show_help() -> None:
    title("HELP / NOTES")
    print("""
Usage:
  python3 0p3nSSL_T00lK1t.py
  python3 0p3nSSL_T00lK1t.py --help

Notes:
  - Generated filenames are timestamped to avoid accidental overwrite.
  - RSA private keys can be generated as encrypted AES-256 PKCS#8 PEM files
    or as unencrypted PKCS#8 PEM files.
  - Unencrypted private keys are sensitive. Store them only in protected paths.
  - Encrypted private keys require the password whenever they are loaded for CSR,
    certificate signing, root CA creation or PKCS#12 creation.
  - SAN input accepts values such as:
    subjectAltName=DNS:www.example.com,DNS:example.com,IP:10.0.0.1,email:admin@example.com
  - DNS TXT DCV checks query public resolvers 1.1.1.1 and 8.8.8.8.
""".strip())


# ---------------------------
# Crypto backend
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
        ok("cryptography backend: OK")
        return True

    warn("cryptography not found. Trying to install via pip...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=False)
    except Exception as exc:
        err(f"Install attempt failed: {exc}")
        return False

    CRYPTO = load_crypto()
    if CRYPTO is None:
        err("cryptography still unavailable. Install it manually: python3 -m pip install cryptography")
        return False

    ok("cryptography installed and loaded.")
    return True


# ---------------------------
# File helpers
# ---------------------------

def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def write_file_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


# ---------------------------
# PEM/Cert helpers
# ---------------------------

def cert_not_before(cert) -> Optional[datetime]:
    return getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)


def cert_not_after(cert) -> Optional[datetime]:
    return getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)


def load_private_key_pem(path: str):
    if not ensure_crypto():
        return None
    try:
        data = read_file_bytes(path)
    except Exception as exc:
        err(f"Cannot read private key: {exc}")
        return None

    pw = getpass("Private key password (empty if none): ")
    password = pw.encode() if pw else None
    try:
        return CRYPTO.serialization.load_pem_private_key(data, password=password)
    except TypeError:
        return CRYPTO.serialization.load_pem_private_key(
            data, password=password, backend=CRYPTO.default_backend()
        )
    except Exception as exc:
        err(f"Failed to load private key: {exc}")
        return None


def load_cert_pem(path: str):
    if not ensure_crypto():
        return None
    try:
        data = read_file_bytes(path)
    except Exception as exc:
        err(f"Cannot read certificate: {exc}")
        return None

    try:
        return CRYPTO.x509.load_pem_x509_certificate(data)
    except TypeError:
        return CRYPTO.x509.load_pem_x509_certificate(data, backend=CRYPTO.default_backend())
    except Exception as exc:
        err(f"Failed to load certificate: {exc}")
        return None


def load_csr_pem(path: str):
    if not ensure_crypto():
        return None
    try:
        data = read_file_bytes(path)
    except Exception as exc:
        err(f"Cannot read CSR: {exc}")
        return None

    try:
        return CRYPTO.x509.load_pem_x509_csr(data)
    except TypeError:
        return CRYPTO.x509.load_pem_x509_csr(data, backend=CRYPTO.default_backend())
    except Exception as exc:
        err(f"Failed to load CSR: {exc}")
        return None


def parse_addext_subject_alt_name(addext: str):
    if not ensure_crypto():
        return None
    addext = addext.strip()
    if not addext:
        return None

    payload = addext.split("=", 1)[1].strip() if addext.lower().startswith("subjectaltname=") else addext
    items = [x.strip() for x in payload.split(",") if x.strip()]
    if not items:
        return None

    general_names = []
    bad = []
    for item in items:
        if ":" not in item:
            bad.append(item)
            continue
        key, value = item.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        try:
            if key == "dns":
                general_names.append(CRYPTO.x509.DNSName(value))
            elif key == "ip":
                general_names.append(CRYPTO.x509.IPAddress(ipaddress.ip_address(value)))
            elif key in {"email", "emailaddress"}:
                general_names.append(CRYPTO.x509.RFC822Name(value))
            elif key == "uri":
                general_names.append(CRYPTO.x509.UniformResourceIdentifier(value))
            else:
                bad.append(item)
        except Exception:
            bad.append(item)

    if bad:
        warn(f"Skipped invalid SAN item(s): {', '.join(bad)}")
    if not general_names:
        return None
    return CRYPTO.x509.SubjectAlternativeName(general_names)


# ---------------------------
# Dump utilities
# ---------------------------

def dump_private_key_text(priv) -> str:
    pub = priv.public_key()
    lines = ["===== PRIVATE KEY ====="]
    if hasattr(priv, "key_size"):
        lines.append(f"Key Size: {priv.key_size}")
    try:
        nums = priv.private_numbers()
        pubn = nums.public_numbers
        lines.extend([
            "Type: RSA",
            f"Public Exponent (e): {pubn.e}",
            f"Modulus (n): {pubn.n.bit_length()} bits",
            f"Modulus (n) hex: {hex(pubn.n)}",
            f"Private Exponent (d): {nums.d.bit_length()} bits",
        ])
    except Exception:
        lines.append("Type: unsupported for detailed dump")

    pem_pub = pub.public_bytes(
        encoding=CRYPTO.serialization.Encoding.PEM,
        format=CRYPTO.serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode(errors="ignore")
    lines.append("\n===== PUBLIC KEY (PEM) =====\n" + pem_pub.strip())
    return "\n".join(lines) + "\n"


def render_general_names(value) -> list[str]:
    lines = []
    try:
        dns = value.get_values_for_type(CRYPTO.x509.DNSName)
        ips = value.get_values_for_type(CRYPTO.x509.IPAddress)
        emails = value.get_values_for_type(CRYPTO.x509.RFC822Name)
        uris = value.get_values_for_type(CRYPTO.x509.UniformResourceIdentifier)
        if dns:
            lines.append(f"    DNS   : {', '.join(dns)}")
        if ips:
            lines.append(f"    IP    : {', '.join(str(x) for x in ips)}")
        if emails:
            lines.append(f"    Email : {', '.join(emails)}")
        if uris:
            lines.append(f"    URI   : {', '.join(uris)}")
    except Exception:
        lines.append(f"    {value}")
    return lines


def dump_cert_text(cert) -> str:
    lines = [
        "===== CERTIFICATE =====\n",
        "Subject",
        f"  {cert.subject.rfc4514_string() or '(empty)'}\n",
        "Issuer",
        f"  {cert.issuer.rfc4514_string() or '(empty)'}\n",
        "Metadata",
        f"  Serial Number : {hex(cert.serial_number)}",
        f"  Version       : {getattr(getattr(cert, 'version', None), 'name', 'unknown')}",
        f"  Signature Hash: {cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'unknown'}\n",
        "Validity (UTC)",
        f"  Not Before: {fmt_dt(cert_not_before(cert))}",
        f"  Not After : {fmt_dt(cert_not_after(cert))}\n",
        "Extensions",
    ]
    if not cert.extensions:
        lines.append("  (none)")
        return "\n".join(lines) + "\n"

    for ext in cert.extensions:
        name = getattr(ext.oid, "_name", None) or ext.oid.dotted_string
        lines.append(f"  - {name} (critical={ext.critical})")
        value = ext.value
        try:
            if isinstance(value, CRYPTO.x509.SubjectAlternativeName):
                lines.extend(render_general_names(value))
            elif isinstance(value, CRYPTO.x509.BasicConstraints):
                lines.append(f"    CA         : {value.ca}")
                lines.append(f"    Path Length: {value.path_length}")
            elif isinstance(value, CRYPTO.x509.KeyUsage):
                lines.append(f"    digital_signature : {value.digital_signature}")
                lines.append(f"    key_encipherment  : {value.key_encipherment}")
                lines.append(f"    key_cert_sign     : {value.key_cert_sign}")
                lines.append(f"    crl_sign          : {value.crl_sign}")
            elif isinstance(value, CRYPTO.x509.ExtendedKeyUsage):
                usages = [getattr(oid, "_name", None) or oid.dotted_string for oid in value]
                lines.append(f"    {', '.join(usages) if usages else '(empty)'}")
            else:
                lines.append(f"    {value}")
        except Exception:
            lines.append("    (cannot render extension)")
    return "\n".join(lines) + "\n"


def dump_csr_text(csr) -> str:
    lines = [
        "===== CSR (PKCS#10) =====\n",
        "Subject",
        f"  {csr.subject.rfc4514_string() or '(empty)'}\n",
        "Public Key",
    ]
    try:
        pub = csr.public_key()
        lines.append(f"  Type    : {pub.__class__.__name__}")
        if hasattr(pub, "key_size"):
            lines.append(f"  Key Size: {pub.key_size}")
        try:
            nums = pub.public_numbers()
            if hasattr(nums, "e") and hasattr(nums, "n"):
                lines.append(f"  Exponent: {nums.e}")
                lines.append(f"  Modulus : {nums.n.bit_length()} bits")
        except Exception:
            pass
    except Exception as exc:
        lines.append(f"  Cannot read public key: {exc}")

    lines.append("\nSignature")
    try:
        lines.append(f"  Signature Valid: {csr.is_signature_valid}")
    except Exception:
        lines.append("  Signature Valid: unknown")

    lines.append("\nRequested Extensions")
    try:
        if not csr.extensions:
            lines.append("  (none)")
        for ext in csr.extensions:
            name = getattr(ext.oid, "_name", None) or ext.oid.dotted_string
            lines.append(f"  - {name} (critical={ext.critical})")
            if isinstance(ext.value, CRYPTO.x509.SubjectAlternativeName):
                lines.extend(render_general_names(ext.value))
            else:
                lines.append(f"    {ext.value}")
    except Exception:
        lines.append("  Cannot read extensions")
    return "\n".join(lines) + "\n"


# ---------------------------
# Network helpers
# ---------------------------

def fetch_server_leaf_cert_der(host: str, port: int, timeout: int = 10) -> bytes:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def http_get(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "Python"})
    with urlopen(req, timeout=20) as resp:
        return resp.read()


def http_post(url: str, body: bytes, content_type: str) -> bytes:
    req = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": "Python"},
    )
    with urlopen(req, timeout=20) as resp:
        return resp.read()


def extract_aia_uris(cert) -> Tuple[Optional[str], Optional[str]]:
    ocsp_url = None
    issuer_url = None
    try:
        from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for desc in aia:
            loc = desc.access_location
            if not isinstance(loc, CRYPTO.x509.UniformResourceIdentifier):
                continue
            if desc.access_method == AuthorityInformationAccessOID.OCSP and ocsp_url is None:
                ocsp_url = loc.value
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and issuer_url is None:
                issuer_url = loc.value
    except Exception:
        pass
    return ocsp_url, issuer_url


def do_ocsp_query(leaf_cert, issuer_cert, ocsp_url: str) -> str:
    try:
        from cryptography.utils import CryptographyDeprecationWarning  # type: ignore
    except Exception:
        class CryptographyDeprecationWarning(Warning):
            pass

    def ocsp_dt(obj, utc_attr: str, legacy_attr: str) -> Optional[datetime]:
        if hasattr(obj, utc_attr):
            try:
                return getattr(obj, utc_attr)
            except Exception:
                return None
        if hasattr(obj, legacy_attr):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=CryptographyDeprecationWarning)
                try:
                    return getattr(obj, legacy_attr)
                except Exception:
                    return None
        return None

    builder = CRYPTO.ocsp.OCSPRequestBuilder().add_certificate(
        leaf_cert, issuer_cert, CRYPTO.hashes.SHA1()
    )
    request_bytes = builder.build().public_bytes(CRYPTO.serialization.Encoding.DER)
    try:
        response_bytes = http_post(ocsp_url, request_bytes, "application/ocsp-request")
        ocsp_resp = CRYPTO.ocsp.load_der_ocsp_response(response_bytes)
    except Exception as exc:
        return f"OCSP query failed: {exc}\n"

    lines = ["===== OCSP RESPONSE =====", f"Response Status: {ocsp_resp.response_status}"]
    if ocsp_resp.response_status != CRYPTO.ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "\n".join(lines) + "\n"

    try:
        lines.append(f"Certificate Status: {ocsp_resp.certificate_status}")
        lines.append(f"This Update (UTC): {fmt_dt(ocsp_dt(ocsp_resp, 'this_update_utc', 'this_update'))}")
        lines.append(f"Next Update (UTC): {fmt_dt(ocsp_dt(ocsp_resp, 'next_update_utc', 'next_update'))}")
        lines.append(f"Revocation Time : {fmt_dt(ocsp_dt(ocsp_resp, 'revocation_time_utc', 'revocation_time'))}")
        lines.append(f"Revocation Reason: {ocsp_resp.revocation_reason}")
    except Exception:
        pass
    return "\n".join(lines) + "\n"


# ---------------------------
# DNS TXT helper
# ---------------------------

def _dns_query_txt_udp(name: str, server: str, timeout: float = 2.0) -> list[str]:
    import random
    import struct

    def enc_qname(q: str) -> bytes:
        out = b""
        for part in q.rstrip(".").split("."):
            if not part:
                continue
            label = part.encode("idna")
            if len(label) > 63:
                raise ValueError("DNS label too long")
            out += bytes([len(label)]) + label
        return out + b"\x00"

    def skip_name(buf: bytes, offset: int) -> int:
        while True:
            if offset >= len(buf):
                raise ValueError("Truncated DNS name")
            length = buf[offset]
            if length == 0:
                return offset + 1
            if (length & 0xC0) == 0xC0:
                return offset + 2
            offset += 1 + length

    txid = random.randint(0, 0xFFFF)
    packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    packet += enc_qname(name) + struct.pack("!HH", 16, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return []
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != txid or flags & 0x000F:
        return []

    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset) + 4

    values = []
    for _ in range(ancount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rclass != 1 or rtype != 16:
            continue
        p = 0
        chunks = []
        while p < len(rdata):
            ln = rdata[p]
            p += 1
            chunks.append(rdata[p:p + ln])
            p += ln
        values.append(b"".join(chunks).decode("utf-8", errors="replace"))
    return values


def _dns_query_txt(name: str, server: str, timeout: float = 2.0) -> list[str]:
    try:
        return _dns_query_txt_udp(name, server, timeout=timeout)
    except Exception:
        return []


# ---------------------------
# Option handlers
# ---------------------------

def opt_install_check() -> None:
    title("INSTALL/CHECK PYTHON CRYPTO BACKEND")
    ensure_crypto()


def opt_create_rsa_privkey() -> None:
    title("CREATE RSA PRIVATE KEY")
    if not ensure_crypto():
        return

    print("1) RSA 2048")
    print("2) RSA 4096")
    bits_choice = prompt("Key size: ").strip()
    bits = {"1": 2048, "2": 4096}.get(bits_choice)
    if bits is None:
        err("Invalid key size selection.")
        return

    print("\n1) Encrypted with password (AES-256)")
    print("2) Unencrypted / no password")
    mode_choice = prompt("Protection mode: ").strip()
    if mode_choice not in {"1", "2"}:
        err("Invalid protection mode selection.")
        return

    encryption_algorithm = None
    protection_label = "unencrypted"
    if mode_choice == "1":
        pw1 = getpass("Encryption password (AES-256): ")
        if not pw1:
            err("Empty password not allowed for encrypted private keys.")
            return
        pw2 = getpass("Confirm password: ")
        if pw1 != pw2:
            err("Passwords do not match.")
            return
        encryption_algorithm = CRYPTO.serialization.BestAvailableEncryption(pw1.encode())
        protection_label = "AES-256 encrypted"
    else:
        warn("Generating an unencrypted private key. Protect the output file carefully.")
        encryption_algorithm = CRYPTO.serialization.NoEncryption()

    filename = f"priv_key_RSA{bits}_{'enc' if mode_choice == '1' else 'nopass'}_{ts()}.pem"
    priv = CRYPTO.rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = priv.private_bytes(
        encoding=CRYPTO.serialization.Encoding.PEM,
        format=CRYPTO.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    write_file_bytes(filename, pem)
    ok(f"Key generated ({bits}-bit, {protection_label}) --> {filename}")


def opt_dump_key() -> None:
    title("DUMP KEY DATA")
    if not ensure_crypto():
        return
    list_dir()
    key_path = prompt("Private Key PEM file: ").strip()
    if not key_path:
        return

    print("\n1) Dump Public Key")
    print("2) Dump Private Key (CONFIDENTIAL DATA)")
    choice = prompt("Selection: ").strip()
    priv = load_private_key_pem(key_path)
    if priv is None:
        return

    if choice == "1":
        pub = priv.public_key()
        pem_pub = pub.public_bytes(
            encoding=CRYPTO.serialization.Encoding.PEM,
            format=CRYPTO.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print(pem_pub.decode(errors="ignore"))
    elif choice == "2":
        warn("CONFIDENTIAL DATA")
        print(dump_private_key_text(priv))
    else:
        err("Invalid selection.")


def opt_create_root_selfsigned() -> None:
    title("CREATE ROOT SELF-SIGNED CERTIFICATE/CA")
    if not ensure_crypto():
        return
    list_dir()
    out_name = f"root_cert_selfsigned_{ts()}.pem"
    key_path = prompt("Private Key file (RSA 4096 recommended): ").strip()
    cn = prompt("Common Name (e.g. Lab Root CA): ").strip()
    org = prompt("Organization (e.g. Lab CA): ").strip()
    country = prompt("Country (2-letter code, e.g. US/IT): ").strip()
    days_s = prompt("Days of Validity (e.g. 365): ").strip()
    try:
        days = int(days_s)
    except Exception:
        err("Invalid validity days.")
        return

    priv = load_private_key_pem(key_path)
    if priv is None:
        return

    name = CRYPTO.x509.Name([
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COUNTRY_NAME, country),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.ORGANIZATION_NAME, org),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COMMON_NAME, cn),
    ])
    now = utc_now()
    cert = (
        CRYPTO.x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(CRYPTO.x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(CRYPTO.x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
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
        .add_extension(CRYPTO.x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)
        .sign(private_key=priv, algorithm=CRYPTO.hashes.SHA256())
    )
    write_file_bytes(out_name, cert.public_bytes(CRYPTO.serialization.Encoding.PEM))
    ok(f"Root certificate generated --> {out_name}")


def opt_create_csr() -> None:
    title("CREATE CSR/PKCS#10")
    if not ensure_crypto():
        return
    list_dir()
    req_name = f"csr_request_{ts()}.csr"
    priv_path = prompt("Private Key file: ").strip()
    cn = prompt("Common Name (e.g. www.example.com): ").strip()
    org = prompt("Organization (e.g. Example): ").strip()
    country = prompt("Country (2-letter code, e.g. US/IT): ").strip()
    print("SAN example: subjectAltName=DNS:www.example.com,DNS:example.com,IP:10.0.0.1,email:admin@example.com")
    addtext = prompt("Additional Text / SAN (optional): ").strip()

    priv = load_private_key_pem(priv_path)
    if priv is None:
        return

    subject = CRYPTO.x509.Name([
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COUNTRY_NAME, country),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.ORGANIZATION_NAME, org),
        CRYPTO.x509.NameAttribute(CRYPTO.NameOID.COMMON_NAME, cn),
    ])
    builder = CRYPTO.x509.CertificateSigningRequestBuilder().subject_name(subject)
    san = parse_addext_subject_alt_name(addtext)
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    csr = builder.sign(priv, CRYPTO.hashes.SHA256())
    write_file_bytes(req_name, csr.public_bytes(CRYPTO.serialization.Encoding.PEM))
    ok(f"Request generated --> {req_name}")


def opt_issue_cert() -> None:
    title("ISSUE CERTIFICATE WITH CSR AND LOCAL/TARGET CA")
    if not ensure_crypto():
        return
    list_dir()
    issued = f"signed_issued_cert_{ts()}.pem"
    csr_path = prompt("CSR file: ").strip()
    ca_cert_path = prompt("Root CA Cert file: ").strip()
    ca_key_path = prompt("Root CA Key file: ").strip()
    days_s = prompt("Days of Validity (e.g. 365): ").strip()
    try:
        days = int(days_s)
    except Exception:
        err("Invalid validity days.")
        return

    csr = load_csr_pem(csr_path)
    ca_cert = load_cert_pem(ca_cert_path)
    ca_key = load_private_key_pem(ca_key_path)
    if csr is None or ca_cert is None or ca_key is None:
        return

    now = utc_now()
    builder = (
        CRYPTO.x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(CRYPTO.x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
    )

    try:
        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)
    except Exception:
        pass

    try:
        from cryptography.x509.oid import ExtensionOID
        builder.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except Exception:
        builder = builder.add_extension(CRYPTO.x509.BasicConstraints(ca=False, path_length=None), critical=True)

    cert = builder.sign(private_key=ca_key, algorithm=CRYPTO.hashes.SHA256())
    write_file_bytes(issued, cert.public_bytes(CRYPTO.serialization.Encoding.PEM))
    ok(f"Issued certificate generated --> {issued}")


def opt_create_pkcs12() -> None:
    title("CREATE PKCS#12")
    if not ensure_crypto():
        return
    list_dir()
    out_name = f"PKCS12_{ts()}.pfx"
    priv_path = prompt("Client PEM Private Key file: ").strip()
    cert_path = prompt("Client PEM Certificate file: ").strip()
    chain_path = prompt("PEM Certificate Chain file related (optional): ").strip()

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
            for block in blocks:
                try:
                    chain_certs.append(CRYPTO.x509.load_pem_x509_certificate(block))
                except TypeError:
                    chain_certs.append(CRYPTO.x509.load_pem_x509_certificate(block, backend=CRYPTO.default_backend()))
        except Exception as exc:
            warn(f"Could not read chain file, continuing without chain: {exc}")

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
    ok(f"PKCS#12 generated --> {out_name}")


def opt_dump_cert_local() -> None:
    title("DUMP CERTIFICATE DATA")
    if not ensure_crypto():
        return
    list_dir()
    cert_path = prompt("Certificate CRT/PEM file: ").strip()
    cert = load_cert_pem(cert_path)
    if cert is None:
        return

    print("\n1) Dump just data/subject/issuer")
    print("2) Dump ALL Certificate Data")
    choice = prompt("Selection: ").strip()
    if choice == "1":
        print(f"subject={cert.subject.rfc4514_string()}")
        print(f"issuer={cert.issuer.rfc4514_string()}")
        print(f"notBefore(UTC)={fmt_dt(cert_not_before(cert))}")
        print(f"notAfter(UTC)={fmt_dt(cert_not_after(cert))}")
    elif choice == "2":
        print(dump_cert_text(cert))
    else:
        err("Invalid selection.")


def opt_dump_cert_online() -> None:
    title("DUMP ONLINE CERTIFICATE DATA")
    if not ensure_crypto():
        return
    host = prompt("Site to be checked (e.g. google.com): ").strip()
    port_s = prompt("Service port exposed (e.g. 443): ").strip()
    try:
        port = int(port_s)
    except Exception:
        err("Invalid port.")
        return

    try:
        der = fetch_server_leaf_cert_der(host, port)
    except Exception as exc:
        err(f"TLS fetch failed: {exc}")
        return

    try:
        leaf = CRYPTO.x509.load_der_x509_certificate(der)
    except TypeError:
        leaf = CRYPTO.x509.load_der_x509_certificate(der, backend=CRYPTO.default_backend())
    print(dump_cert_text(leaf))

    if not yes(prompt("Save certificate locally and optionally check OCSP? (Yes/No): ")):
        print("Ok |m|")
        return

    target_pem = f"Cert_Dumped_{ts()}.pem"
    write_file_bytes(target_pem, leaf.public_bytes(CRYPTO.serialization.Encoding.PEM))
    ok(f"Certificate saved --> {target_pem}")

    if not yes(prompt("Check Certificate state via OCSP? (Yes/No): ")):
        print("Ok |m|")
        return

    ocsp_url, issuer_url = extract_aia_uris(leaf)
    if not ocsp_url or not issuer_url:
        err("Could not extract OCSP/CA Issuers URIs from certificate AIA.")
        return

    base = f"Issuer_for_OCSP_query_{ts()}"
    cer_path = f"{base}.cer"
    pem_path = f"{base}.pem"
    try:
        issuer_bytes = http_get(issuer_url)
        write_file_bytes(cer_path, issuer_bytes)
    except Exception as exc:
        err(f"Issuer download failed: {exc}")
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
        err("Cannot parse issuer certificate.")
        return

    write_file_bytes(pem_path, issuer.public_bytes(CRYPTO.serialization.Encoding.PEM))
    ok(f"Issuer Certificate CER --> {cer_path}")
    ok(f"Issuer Certificate PEM --> {pem_path}")
    print(do_ocsp_query(leaf, issuer, ocsp_url))


def opt_verify_csr() -> None:
    title("CSR VERIFICATION")
    if not ensure_crypto():
        return
    list_dir()
    csr_path = prompt("CSR file: ").strip()
    csr = load_csr_pem(csr_path)
    if csr is None:
        return

    try:
        print(f"CSR signature valid: {csr.is_signature_valid}")
    except Exception:
        warn("CSR signature validity unknown.")
    title("INSPECTING CSR")
    print(dump_csr_text(csr))


def opt_dump_pkcs12() -> None:
    title("DUMP PKCS#12 DATA")
    if not ensure_crypto():
        return
    list_dir()
    ts0 = ts()
    extracted_cert = f"Extracted_Cert_{ts0}.pem"
    extracted_chain = f"Extracted_Chain_{ts0}.pem"
    extracted_priv = f"Extracted_PrivKey_{ts0}.pem"

    pfx_path = prompt("PKCS#12 PFX file: ").strip()
    print("\n1) General Inspection")
    print("2) Extract Cert PEM and Chain PEM")
    print("3) Extract Priv Key (CONFIDENTIAL DATA)")
    choice = prompt("Selection: ").strip()

    try:
        pfx_bytes = read_file_bytes(pfx_path)
    except Exception as exc:
        err(f"Cannot read PFX: {exc}")
        return

    pw = getpass("PKCS#12 password (empty if none): ")
    password = pw.encode() if pw else None
    try:
        key, cert, cas = CRYPTO.pkcs12.load_key_and_certificates(pfx_bytes, password=password)
    except Exception as exc:
        err(f"PKCS#12 parse failed: {exc}")
        return

    if choice == "1":
        print("PKCS#12:")
        print(f"  Has private key: {bool(key)}")
        print(f"  Has leaf cert : {bool(cert)}")
        print(f"  Chain length  : {len(cas) if cas else 0}")
        if cert:
            print("\nLeaf certificate:\n" + dump_cert_text(cert))
    elif choice == "2":
        if cert:
            write_file_bytes(extracted_cert, cert.public_bytes(CRYPTO.serialization.Encoding.PEM))
            ok(f"Extracted Cert PEM file --> {extracted_cert}")
        if cas:
            chain_pem = b"".join(c.public_bytes(CRYPTO.serialization.Encoding.PEM) for c in cas)
            write_file_bytes(extracted_chain, chain_pem)
            ok(f"Extracted Chain PEM file --> {extracted_chain}")
    elif choice == "3":
        if key is None:
            err("No private key in PKCS#12.")
            return
        out_pw = getpass("Output private key encryption password (empty for none): ")
        enc = CRYPTO.serialization.BestAvailableEncryption(out_pw.encode()) if out_pw else CRYPTO.serialization.NoEncryption()
        pem = key.private_bytes(
            encoding=CRYPTO.serialization.Encoding.PEM,
            format=CRYPTO.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        write_file_bytes(extracted_priv, pem)
        ok(f"Extracted Private Key PEM file --> {extracted_priv}")
        warn("CONFIDENTIAL DATA")
    else:
        err("Invalid selection.")


def opt_dcv_dns_txt_precheck() -> None:
    title("DIGICERT DCV - DNS TXT PRECHECK")
    fqdn = prompt("TXT Record FQDN (e.g. _dnsauth.example.com): ").strip()
    if not fqdn:
        return
    expected = prompt("Expected TXT token (optional - press Enter to skip): ").strip()
    resolvers = ["1.1.1.1", "8.8.8.8"]
    any_ok = False
    print("\nQuerying public DNS resolvers...\n")

    for resolver in resolvers:
        print(paint(f"Resolver: {resolver}", C.MAGENTA))
        values = _dns_query_txt(fqdn, resolver, timeout=2.0)
        if not values:
            err("  No TXT record found (or not propagated yet).")
            print()
            continue
        print("  Found TXT:")
        for value in values:
            print(f"   - {value}")
        if expected:
            if any(expected in value for value in values):
                ok("  MATCH: expected token is present on this resolver.")
                any_ok = True
            else:
                err("  NO MATCH: expected token not found on this resolver.")
        else:
            ok("  OK: TXT record(s) present. No token provided for strict match.")
            any_ok = True
        print()

    ok("PRECHECK RESULT: PASS") if any_ok else err("PRECHECK RESULT: FAIL")


# ---------------------------
# Main router
# ---------------------------

def read_option() -> None:
    choice = prompt("Enter choice: ").strip()
    if choice == "0":
        clear_screen(); show_help()
    elif choice == "1":
        clear_screen(); opt_install_check()
    elif choice == "2":
        clear_screen(); opt_create_rsa_privkey()
    elif choice == "3":
        clear_screen(); opt_dump_key()
    elif choice == "4":
        clear_screen(); opt_create_root_selfsigned()
    elif choice == "5":
        clear_screen(); opt_create_csr()
    elif choice == "6":
        clear_screen(); opt_issue_cert()
    elif choice == "7":
        clear_screen(); opt_create_pkcs12()
    elif choice == "8":
        clear_screen(); opt_dump_cert_local()
    elif choice == "9":
        clear_screen(); opt_dump_cert_online()
    elif choice == "10":
        clear_screen(); opt_verify_csr()
    elif choice == "11":
        clear_screen(); opt_dump_pkcs12()
    elif choice == "12":
        clear_screen(); opt_dcv_dns_txt_precheck()
    elif choice == "99":
        print(paint("\nHack the Planet |m|\n", C.GREEN))
        raise SystemExit(0)
    else:
        clear_screen()
        err("Invalid option. Please try again.")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help", "help"}:
        show_help()
        return

    while True:
        show_banner()
        show_menu()
        read_option()
        print()


if __name__ == "__main__":
    main()
