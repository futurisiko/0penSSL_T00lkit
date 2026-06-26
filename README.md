# 0p3nSSL T00lK1t

Small interactive toolkit for common OpenSSL and certificate operations.

It ships two implementations:

- `0p3nSSL_T00lK1t.sh` — Bash wrapper around OpenSSL, `dig` and `curl`.
- `0p3nSSL_T00lK1t.py` — Python 3 implementation using `cryptography`, stdlib TLS sockets and a built-in DNS TXT helper.

## Features

| Option | Feature |
|---:|---|
| 0 | Help / Notes |
| 1 | Install or check requirements |
| 2 | Generate RSA private keys: 2048 or 4096 bit, encrypted or unencrypted |
| 3 | Dump public/private key data |
| 4 | Create a root self-signed CA certificate |
| 5 | Create a CSR/PKCS#10 request, with optional SAN |
| 6 | Sign a CSR with a local CA certificate/key |
| 7 | Create a PKCS#12/PFX bundle |
| 8 | Dump local certificate data |
| 9 | Dump a remote TLS certificate and optionally check OCSP |
| 10 | Verify and inspect a local CSR |
| 11 | Inspect or extract data from a PKCS#12/PFX file |
| 12 | Check DNS TXT records for DigiCert DCV pre-validation |

## Requirements

### Bash version

- Bash
- OpenSSL
- `dig` from `dnsutils` / `bind-utils`
- `curl`

On Debian/Ubuntu-based systems, option `1` installs:

```bash
sudo apt-get install -y openssl dnsutils curl
```

### Python version

- Python 3
- `cryptography`

Install manually when needed:

```bash
python3 -m pip install cryptography
```

## Usage

```bash
chmod +x 0p3nSSL_T00lK1t.sh
./0p3nSSL_T00lK1t.sh
```

```bash
chmod +x 0p3nSSL_T00lK1t.py
python3 0p3nSSL_T00lK1t.py
```

Help:

```bash
./0p3nSSL_T00lK1t.sh --help
python3 0p3nSSL_T00lK1t.py --help
```
