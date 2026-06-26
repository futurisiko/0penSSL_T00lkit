# 0p3nSSL T00lkit

A small interactive toolkit that groups common OpenSSL and X.509 certificate tasks into a menu-driven workflow.

The repository contains two implementations:

- `0p3nSSL_T00lK1t.sh` — shell version that wraps OpenSSL, `dig`, `curl`, and standard Unix tools.
- `0p3nSSL_T00lK1t.py` — Python version that performs the same core tasks using Python's `ssl` module and the `cryptography` package.

The toolkit is intended for administrators, lab environments, certificate troubleshooting, CSR generation, local CA testing, PKCS#12 handling, online TLS certificate inspection, OCSP checks, and DigiCert DNS TXT DCV prechecks.

---

## Features

### Key tools

- Generate AES-256 encrypted RSA private keys.
- Choose between RSA 2048-bit and RSA 4096-bit key sizes.
- Dump public key information from a private key.
- Dump private key details when explicitly requested.

### Certificate creation tools

- Create a local root self-signed certificate / CA certificate.
- Generate a generic PKCS#10 CSR.
- Add Subject Alternative Name entries to a CSR.
- Issue a certificate from a CSR using a local CA certificate and CA private key.
- Create a PKCS#12 / PFX bundle containing a private key, certificate, and optional chain.

### Certificate dump and validation tools

- Dump local certificate subject, issuer, and validity dates.
- Dump full local certificate details.
- Connect to a remote TLS service and dump the presented certificate.
- Optionally save the remote TLS leaf certificate locally.
- Optionally perform an OCSP status check using the certificate AIA information.
- Verify and inspect a local CSR.
- Inspect or extract content from a PKCS#12 / PFX file.
- Check DNS TXT records for DigiCert domain-control validation prechecks.

---

## Requirements

### Python version

Required:

- Python 3
- `cryptography` Python package

The Python script includes an option to check whether `cryptography` is available and attempts to install it with `pip` when missing.

Recommended manual install:

```bash
python3 -m pip install cryptography
```

Run:

```bash
python3 0p3nSSL_T00lK1t.py
```

On Windows, use the appropriate Python launcher if needed:

```powershell
py 0p3nSSL_T00lK1t.py
```

### Shell version

Required:

- OpenSSL
- `dig` from `dnsutils` or equivalent package
- `curl` for issuer certificate download during OCSP checks
- Standard Unix tools such as `awk`, `sed`, `tput`, `ls`, and `date`

The shell script option `1` installs `openssl` and `dnsutils` with `apt`, so it is mainly aimed at Debian/Ubuntu-like systems.

```bash
chmod +x 0p3nSSL_T00lK1t.sh
./0p3nSSL_T00lK1t.sh
```

If your `/bin/sh` does not support interactive `read -p` prompts, run it with Bash:

```bash
bash 0p3nSSL_T00lK1t.sh
```

---

## Menu overview

| Option | Name | What it does |
|---:|---|---|
| `1` | Install / check requirements | Shell: installs `openssl` and `dnsutils` with `apt`. Python: checks and attempts to install `cryptography`. |
| `2` | Create RSA private key | Generates an AES-256 encrypted RSA private key, either 2048-bit or 4096-bit. |
| `3` | Dump private or public key data | Reads a PEM private key and prints either the public key or private key details. |
| `4` | Create root self-signed certificate | Creates a self-signed certificate using an existing private key. |
| `5` | Create CSR / PKCS#10 request | Creates a CSR from an existing private key and optional Subject Alternative Name input. |
| `6` | Issue certificate with CSR and CA | Signs a CSR using a local CA certificate and CA private key. |
| `7` | Create PKCS#12 | Builds a `.pfx` / PKCS#12 bundle from a private key, certificate, and optional certificate chain. |
| `8` | Dump local certificate data | Prints local certificate metadata or full certificate details. |
| `9` | Dump online TLS certificate data | Connects to a host and port, dumps the remote TLS certificate, can save it, and can run OCSP checks. |
| `10` | Verify and dump CSR data | Verifies CSR signature validity and prints CSR details. |
| `11` | Verify and dump PKCS#12 data | Inspects a PFX file or extracts certificate, chain, or private key material. |
| `12` | DigiCert DCV DNS TXT precheck | Queries public DNS resolvers for a TXT record and optionally checks whether an expected token is present. |
| `99` | Exit | Exits the toolkit. |

---

## Detailed option reference

### 1. Install / check requirements

Shell version:

```bash
sudo apt update
sudo apt install openssl dnsutils -y
```

Python version:

- Checks whether `cryptography` can be imported.
- If missing, attempts to run:

```bash
python -m pip install cryptography
```

Note: the shell version also uses `curl` for OCSP issuer certificate download, but the install option only installs `openssl` and `dnsutils`. Install `curl` manually if it is missing.

---

### 2. Create an AES-256 encrypted RSA private key

Prompts:

- RSA key size:
  - `1` = RSA 2048-bit
  - `2` = RSA 4096-bit
- Private key encryption password
- Password confirmation in the Python version

Output filename:

```text
priv_key_<YYYYMMDD_HHMMSS>.pem
```

Security note: generated private keys are sensitive. Do not commit them to Git and do not share them unless absolutely required.

---

### 3. Dump private or public key data

Prompts:

- Private key PEM file path
- Dump mode:
  - `1` = print public key
  - `2` = print private key details

The private-key dump mode exposes confidential key material. Use it only in a safe terminal session and avoid saving terminal logs containing this output.

---

### 4. Create a root self-signed certificate / CA certificate

Prompts:

- Private key file
- Common Name
- Organization
- Country code / X.509 `C` field
- Validity in days

Output filename:

```text
root_cert_selfsigned_<YYYYMMDD_HHMMSS>.pem
```

Implementation notes:

- The Python version creates a CA-style certificate with `BasicConstraints(ca=True)`, CA key usage, and a Subject Key Identifier.
- The shell version uses `openssl req -x509` with the provided subject values.

Recommended usage: use a 4096-bit RSA key for local root CA testing.

---

### 5. Create a generic CSR / PKCS#10 request

Prompts:

- Private key file
- Common Name
- Organization
- Country code / X.509 `C` field
- Optional additional extension text

Output filename:

```text
csr_request_<YYYYMMDD_HHMMSS>.csr
```

Subject Alternative Name example:

```text
subjectAltName=DNS:www.example.local,DNS:example.local,IP:10.0.0.1,email:admin@example.com,URI:https://example.com
```

Supported SAN item types in the Python version:

- `DNS:<name>`
- `IP:<address>`
- `email:<address>` or `emailAddress:<address>`
- `URI:<uri>`

The shell version passes the additional text to OpenSSL with `-addext`.

---

### 6. Issue a certificate using a CSR and local CA

Prompts:

- CSR file
- Root CA certificate file
- Root CA private key file
- Validity in days

Output filename:

```text
signed_issued_cert_<YYYYMMDD_HHMMSS>.pem
```

Implementation notes:

- The shell version signs with `openssl x509 -req`, uses `-copy_extensions copyall`, and then runs `openssl verify` against the provided CA file.
- The Python version copies CSR extensions when available and adds `BasicConstraints(ca=False)` if missing.

Security note: the CA private key is highly sensitive. Keep it encrypted and do not store it in the repository.

---

### 7. Create a PKCS#12 / PFX bundle

Prompts:

- Client PEM private key file
- Client PEM certificate file
- PEM certificate chain file
- PKCS#12 export password, depending on implementation and OpenSSL prompts

Output filename:

```text
PKCS12_<YYYYMMDD_HHMMSS>.pfx
```

The generated file can contain private key material. Treat `.pfx` / `.p12` files as confidential.

---

### 8. Dump local certificate data

Prompts:

- Certificate CRT/PEM file
- Dump mode:
  - `1` = subject, issuer, and validity dates
  - `2` = full certificate dump

Useful for quickly checking certificate metadata, expiration dates, SANs, key usage, issuer, and other extensions.

---

### 9. Dump online TLS certificate data and optionally check OCSP

Prompts:

- Target host, for example `www.example.com`
- Target service port, for example `443`
- Whether to save the remote certificate locally
- Whether to check certificate state through OCSP

Possible output files:

```text
Cert_Dumped_<YYYYMMDD_HHMMSS>.pem
Issuer_for_OCSP_query_<YYYYMMDD_HHMMSS>.cer
Issuer_for_OCSP_query_<YYYYMMDD_HHMMSS>.pem
```

What the option does:

1. Connects to the target TLS service.
2. Reads and prints the leaf certificate.
3. Optionally saves the leaf certificate in PEM format.
4. Extracts OCSP and CA Issuers URLs from the certificate AIA extension.
5. Downloads the issuer certificate.
6. Converts the issuer certificate to PEM when needed.
7. Performs an OCSP request and prints the response.

Implementation notes:

- The shell version uses `openssl s_client`, `openssl x509`, `curl`, and `openssl ocsp`.
- The Python version uses `ssl` for the TLS connection, `urllib` for issuer / OCSP HTTP requests, and `cryptography` for certificate parsing and OCSP request handling.
- The Python TLS connection uses Python's default SSL context, so it may fail when the remote certificate is expired, self-signed, untrusted, or otherwise invalid.

---

### 10. Verify and dump CSR / PKCS#10 data locally

Prompts:

- CSR file

What it does:

- Verifies the CSR signature.
- Prints the CSR subject.
- Prints public key details.
- Prints requested extensions such as Subject Alternative Name.

---

### 11. Verify and dump PKCS#12 / PFX data locally

Prompts:

- PKCS#12 / PFX file
- Mode:
  - `1` = general inspection
  - `2` = extract certificate and certificate chain
  - `3` = extract private key

Possible output files:

```text
Extracted_Cert_<YYYYMMDD_HHMMSS>.pem
Extracted_Chain_<YYYYMMDD_HHMMSS>.pem
Extracted_PrivKey_<YYYYMMDD_HHMMSS>.pem
```

Security note: option `3` extracts private key material. The extracted private key file is confidential and must be protected.

---

### 12. DigiCert DCV DNS TXT precheck

Prompts:

- TXT record FQDN, for example `_dnsauth.example.com`
- Expected TXT token, optional

Resolvers checked:

```text
1.1.1.1
8.8.8.8
```

What it does:

- Queries TXT records for the provided FQDN.
- Prints discovered TXT values.
- If an expected token is provided, checks whether that token appears in at least one TXT response.
- Reports whether the precheck passes or fails.

Important notes:

- This is a public DNS propagation precheck. It does not contact DigiCert directly.
- The result depends on DNS propagation and resolver visibility.
- Do not publish real DCV tokens in documentation, issues, screenshots, or commit history.

---

## Generated file naming convention

Most actions generate timestamped files using this format:

```text
<name>_<YYYYMMDD_HHMMSS>.<extension>
```

Examples:

```text
priv_key_20260101_120000.pem
csr_request_20260101_120000.csr
signed_issued_cert_20260101_120000.pem
PKCS12_20260101_120000.pfx
```

Timestamped output reduces accidental overwrites, but generated files may still contain sensitive material.

---

## Security and sensitive data handling

This toolkit can create, read, export, and print sensitive cryptographic material.

Treat the following as confidential:

- Private keys
- Root CA private keys
- PKCS#12 / PFX files
- Extracted private keys
- Private key dumps
- Real DCV TXT tokens
- Internal hostnames or private service names
- Internal CA names, organization names, or certificate subjects when they reveal infrastructure details

Recommended precautions:

- Do not commit generated keys, PFX files, extracted keys, real certificates, or DCV tokens.
- Run the toolkit in a directory that is not automatically synced or published.
- Use strong passwords for encrypted private keys and PFX exports.
- Review shell history, terminal logs, and CI logs before sharing them.
- Add generated sensitive files to `.gitignore` if you use the toolkit inside a Git repository.

---

## Bash vs Python behavior differences

The two scripts expose similar menu items, but they are not byte-for-byte identical implementations.

| Area | Shell version | Python version |
|---|---|---|
| Dependency handling | Uses `apt` to install `openssl` and `dnsutils`. | Checks/imports `cryptography` and attempts `pip install cryptography` if missing. |
| Crypto engine | Calls the OpenSSL CLI. | Uses Python `ssl` and `cryptography`. |
| Root certificate | Uses `openssl req -x509`. | Builds an X.509 CA certificate with explicit CA constraints and key usage. |
| CSR SAN handling | Passes additional text to OpenSSL `-addext`. | Parses SAN entries and adds them through `cryptography`. |
| Certificate issuance | Uses `openssl x509 -req -copy_extensions copyall` and runs `openssl verify`. | Copies CSR extensions and adds `BasicConstraints(ca=False)` if absent. |
| Online certificate dump | Uses `openssl s_client` and OpenSSL parsing. | Uses Python's default SSL context and certificate parsing. |
| OCSP | Uses `curl` and `openssl ocsp`. | Builds and sends OCSP requests using `cryptography` and `urllib`. |
| DNS TXT precheck | Uses `dig`. | Uses a minimal built-in DNS TXT client over UDP with TCP fallback. |

---

## Common workflows

### Create a local test CA and issue a certificate

1. Run option `2` and create a 4096-bit encrypted RSA private key.
2. Run option `4` and create a root self-signed certificate from that key.
3. Run option `2` and create a 2048-bit encrypted RSA private key for the leaf certificate.
4. Run option `5` and create a CSR with the desired Common Name and SAN values.
5. Run option `6` and sign the CSR with the local CA certificate and CA private key.
6. Run option `8` to inspect the issued certificate.

### Build a PFX bundle

1. Prepare a private key, certificate, and optional certificate chain.
2. Run option `7`.
3. Protect the generated `.pfx` file as sensitive material.

### Check a public TLS endpoint

1. Run option `9`.
2. Enter the target hostname and port.
3. Review the certificate details.
4. Optionally save the certificate and perform an OCSP check.

### Precheck a DigiCert DNS TXT validation record

1. Create or update the required DNS TXT record.
2. Run option `12`.
3. Enter the TXT record FQDN.
4. Optionally enter the expected token.
5. Confirm that at least one public resolver sees the expected TXT value.

---

### Python online certificate dump fails but Bash works

The Python version uses Python's default SSL verification behavior. It can fail for expired, self-signed, untrusted, hostname-mismatched, or otherwise invalid certificates. The shell version may still be able to display the certificate because `openssl s_client` can retrieve certificate data even when verification is not successful.

---
