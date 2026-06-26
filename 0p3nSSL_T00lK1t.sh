#!/usr/bin/env bash
# 0p3nSSL T00lK1t - Bash implementation
# by Futurisiko


set -o pipefail

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    colorreset=$(tput sgr0)
    red=$(tput setaf 1)
    green=$(tput setaf 2)
    orange=$(tput setaf 3)
    blue=$(tput setaf 4)
    purple=$(tput setaf 5)
    cyan=$(tput setaf 6)
    bold=$(tput bold)
else
    colorreset=""
    red=""
    green=""
    orange=""
    blue=""
    purple=""
    cyan=""
    bold=""
fi

msg_ok() { printf '%b\n' "${green}$*${colorreset}"; }
msg_warn() { printf '%b\n' "${orange}$*${colorreset}"; }
msg_err() { printf '%b\n' "${red}$*${colorreset}"; }
msg_title() { printf '\n%b\n\n' "${bold}${cyan}$*${colorreset}"; }
ts() { date +"%Y%m%d_%H%M%S"; }

show_banner() {
    printf '%b\n' "${purple}-----------------------------------

.d88b.                            8
8P  Y8 88b. .d88b 8d8b. d88b d88b 8
8b  d8 8  8 8.dP  8P Y8  Yb.  Yb. 8
 Y88P  88P   Y88P 8   8 Y88P Y88P 8
       8
88888             8 8    w  w
  8   .d8b. .d8b. 8 8.dP w w8ww
  8   8  .8 8  .8 8 88b  8  8
  8    Y8P   Y8P  8 8 Yb 8  Y8P

--------------------by-Futurisiko--${colorreset}"
}

show_help() {
    msg_title "HELP / NOTES"
    cat <<'EOF'
Usage:
  ./0p3nSSL_T00lK1t.sh
  ./0p3nSSL_T00lK1t.sh --help

Notes:
  - Generated filenames are timestamped to avoid accidental overwrite.
  - RSA private keys can be generated as AES-256 encrypted PEM files or as
    unencrypted PEM files.
  - Unencrypted private keys are sensitive. Store them only in protected paths.
  - Encrypted private keys require the passphrase whenever OpenSSL loads them.
  - SAN input accepts values such as:
    subjectAltName=DNS:www.example.com,DNS:example.com,IP:10.0.0.1,email:admin@example.com
  - DNS TXT DCV checks query public resolvers 1.1.1.1 and 8.8.8.8.
EOF
}

show_menu() {
    printf '\n%b\n' "${green}${bold}Menu:${colorreset}"
    printf '\n%b\n' "${orange}Utility${colorreset}"
    echo "0) Help / Notes"
    echo "1) Install Requirements"
    printf '\n%b\n' "${orange}Key Tools${colorreset}"
    echo "2) Create RSA Private Key - encrypted or unencrypted (PEM)"
    echo "3) Dump Private or Public Key (PEM) Data"
    printf '\n%b\n' "${orange}Certificate Creation Tools${colorreset}"
    echo "4) Create Root Self-Signed Certificate"
    echo "5) Create Generic CSR/PKCS#10 Request"
    echo "6) Issue Certificate with CSR and Target CA"
    echo "7) Create a PKCS#12 with PrivKey, Cert and CertChain"
    printf '\n%b\n' "${orange}Certificate Dump Tools${colorreset}"
    echo "8) Dump Certificate Data Locally"
    echo "9) Verify and Dump Certificate Data Online"
    echo "10) Verify and Dump CSR/PKCS#10 Data Locally"
    echo "11) Verify and Dump PKCS#12 Data Locally"
    printf '\n%b\n' "${orange}Validation Utility${colorreset}"
    echo "12) Check DNS TXT Entries for Domain Validation"
    printf '\n%b\n' "${orange}99) Exit${colorreset}"
}

install_requirements() {
    msg_title "INSTALLING REQUIREMENTS"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y openssl dnsutils curl
    else
        msg_warn "apt-get not found. Install manually: openssl, dnsutils/bind-utils, curl."
    fi
}

create_rsa_key() {
    msg_title "CREATE RSA PRIVATE KEY"
    local bits mode timestamp filename
    timestamp=$(ts)

    echo "1) RSA 2048"
    echo "2) RSA 4096"
    read -r -p "Key size: " bits_choice
    case "$bits_choice" in
        1) bits=2048 ;;
        2) bits=4096 ;;
        *) msg_err "Invalid key size selection."; return ;;
    esac

    echo
    echo "1) Encrypted with password (AES-256)"
    echo "2) Unencrypted / no password"
    read -r -p "Protection mode: " mode_choice
    case "$mode_choice" in
        1)
            mode="enc"
            filename="priv_key_RSA${bits}_enc_${timestamp}.pem"
            msg_warn "OpenSSL will prompt for the encryption passphrase."
            openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${bits}" -aes-256-cbc -out "$filename"
            ;;
        2)
            mode="nopass"
            filename="priv_key_RSA${bits}_nopass_${timestamp}.pem"
            msg_warn "Generating an unencrypted private key. Protect the output file carefully."
            openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${bits}" -out "$filename"
            ;;
        *) msg_err "Invalid protection mode selection."; return ;;
    esac

    if [ -s "$filename" ]; then
        msg_ok "Key generated (${bits}-bit, ${mode}) --> $filename"
    else
        msg_err "Key generation failed."
        rm -f -- "$filename"
    fi
}

dump_key() {
    msg_title "DUMP KEY DATA"
    ls -l
    echo
    read -r -p "Private Key PEM file: " key_file
    [ -n "$key_file" ] || return

    echo
    echo "1) Dump Public Key"
    printf '2) Dump Private Key (%bCONFIDENTIAL DATA%b)\n\n' "$red" "$colorreset"
    read -r -p "Selection: " selection

    case "$selection" in
        1) openssl pkey -in "$key_file" -pubout ;;
        2)
            msg_warn "CONFIDENTIAL DATA"
            openssl pkey -in "$key_file" -noout -text
            ;;
        *) msg_err "Invalid selection." ;;
    esac
}

create_root_selfsigned() {
    msg_title "CREATE ROOT SELF-SIGNED CERTIFICATE/CA"
    local output
    output="root_cert_selfsigned_$(ts).pem"
    ls -l
    echo
    read -r -p "Private Key file (RSA 4096 recommended): " key_file
    read -r -p "Common Name (e.g. Lab Root CA): " common_name
    read -r -p "Organization (e.g. Lab CA): " organization
    read -r -p "Country (2-letter code, e.g. US/IT): " country
    read -r -p "Days of Validity (e.g. 365): " days

    openssl req -x509 -new -key "$key_file" -sha256 -days "$days" -out "$output" \
        -subj "/C=$country/O=$organization/CN=$common_name"

    [ -s "$output" ] && msg_ok "Root certificate generated --> $output" || msg_err "Root certificate generation failed."
}

create_csr() {
    msg_title "CREATE CSR/PKCS#10"
    local output
    output="csr_request_$(ts).csr"
    ls -l
    echo
    read -r -p "Private Key file: " key_file
    read -r -p "Common Name (e.g. www.example.com): " common_name
    read -r -p "Organization (e.g. Example): " organization
    read -r -p "Country (2-letter code, e.g. US/IT): " country
    echo "SAN example: subjectAltName=DNS:www.example.com,DNS:example.com,IP:10.0.0.1,email:admin@example.com"
    read -r -p "Additional Text / SAN (optional): " addext

    if [ -n "$addext" ]; then
        openssl req -new -key "$key_file" -out "$output" \
            -subj "/C=$country/O=$organization/CN=$common_name" -addext "$addext"
    else
        openssl req -new -key "$key_file" -out "$output" \
            -subj "/C=$country/O=$organization/CN=$common_name"
    fi

    [ -s "$output" ] && msg_ok "Request generated --> $output" || msg_err "CSR generation failed."
}

issue_certificate() {
    msg_title "ISSUE CERTIFICATE WITH CSR AND LOCAL/TARGET CA"
    local output
    output="signed_issued_cert_$(ts).pem"
    ls -l
    echo
    read -r -p "CSR file: " csr_file
    read -r -p "Root CA Cert file: " ca_cert_file
    read -r -p "Root CA Key file: " ca_key_file
    read -r -p "Days of Validity (e.g. 365): " days

    openssl x509 -req -in "$csr_file" -CA "$ca_cert_file" -CAkey "$ca_key_file" \
        -CAcreateserial -out "$output" -days "$days" -sha256 -copy_extensions copyall

    if [ -s "$output" ]; then
        msg_ok "Issued certificate generated --> $output"
        msg_warn "Verifying issued certificate..."
        openssl verify -CAfile "$ca_cert_file" "$output"
    else
        msg_err "Certificate issuance failed."
    fi
}

create_pkcs12() {
    msg_title "CREATE PKCS#12"
    local output args
    output="PKCS12_$(ts).pfx"
    ls -l
    echo
    read -r -p "Client PEM Private Key file: " key_file
    read -r -p "Client PEM Certificate file: " cert_file
    read -r -p "PEM Certificate Chain file related (optional): " chain_file

    args=(-export -out "$output" -inkey "$key_file" -in "$cert_file" -name "tls-cert")
    if [ -n "$chain_file" ]; then
        args+=(-certfile "$chain_file")
    fi

    openssl pkcs12 "${args[@]}"
    [ -s "$output" ] && msg_ok "PKCS#12 generated --> $output" || msg_err "PKCS#12 generation failed."
}

dump_certificate_local() {
    msg_title "DUMP CERTIFICATE DATA"
    ls -l
    echo
    read -r -p "Certificate CRT/PEM file: " cert_file
    echo
    echo "1) Dump just data/subject/issuer"
    echo "2) Dump ALL Certificate Data"
    read -r -p "Selection: " selection

    case "$selection" in
        1) openssl x509 -in "$cert_file" -noout -subject -issuer -dates ;;
        2) openssl x509 -in "$cert_file" -noout -text ;;
        *) msg_err "Invalid selection." ;;
    esac
}

fetch_remote_cert() {
    local host=$1
    local port=$2
    openssl s_client -connect "${host}:${port}" -servername "$host" </dev/null 2>/dev/null | openssl x509 -outform PEM
}

dump_certificate_online() {
    msg_title "DUMP ONLINE CERTIFICATE DATA"
    read -r -p "Site to be checked (e.g. google.com): " host
    read -r -p "Service port exposed (e.g. 443): " port
    echo

    if ! fetch_remote_cert "$host" "$port" | openssl x509 -noout -text; then
        msg_err "TLS certificate fetch failed."
        return
    fi

    echo
    read -r -p "Save certificate locally and optionally check OCSP? (Yes/No): " save_local
    case "$save_local" in
        Y|y|Yes|yes)
            local target_cert ocsp_url ca_issuer_url issuer_base
            target_cert="Cert_Dumped_$(ts).pem"
            fetch_remote_cert "$host" "$port" > "$target_cert"
            if [ ! -s "$target_cert" ]; then
                msg_err "Certificate save failed."
                rm -f -- "$target_cert"
                return
            fi
            msg_ok "Certificate saved --> $target_cert"

            read -r -p "Check Certificate state via OCSP? (Yes/No): " check_ocsp
            case "$check_ocsp" in
                Y|y|Yes|yes)
                    ocsp_url=$(openssl x509 -in "$target_cert" -noout -ocsp_uri 2>/dev/null | head -n 1)
                    ca_issuer_url=$(openssl x509 -in "$target_cert" -noout -text 2>/dev/null | awk -F'URI:' '/CA Issuers - URI:/{print $2; exit}' | tr -d '[:space:]')
                    if [ -z "$ocsp_url" ] || [ -z "$ca_issuer_url" ]; then
                        msg_err "Could not extract OCSP or CA Issuers URI."
                        return
                    fi
                    issuer_base="Issuer_for_OCSP_query_$(ts)"
                    curl -fsSL -o "${issuer_base}.cer" "$ca_issuer_url"
                    openssl x509 -in "${issuer_base}.cer" -inform DER -out "${issuer_base}.pem"
                    msg_ok "Issuer Certificate CER --> ${issuer_base}.cer"
                    msg_ok "Issuer Certificate PEM --> ${issuer_base}.pem"
                    openssl ocsp -issuer "${issuer_base}.pem" -cert "$target_cert" -url "$ocsp_url" -resp_text
                    ;;
                *) echo "Ok |m|" ;;
            esac
            ;;
        *) echo "Ok |m|" ;;
    esac
}

verify_csr() {
    msg_title "CSR VERIFICATION"
    ls -l
    echo
    read -r -p "CSR file: " csr_file
    echo
    openssl req -in "$csr_file" -noout -verify
    msg_title "INSPECTING CSR"
    openssl req -in "$csr_file" -noout -text
}

dump_pkcs12() {
    msg_title "DUMP PKCS#12 DATA"
    local timestamp extracted_cert extracted_chain extracted_priv
    timestamp=$(ts)
    extracted_cert="Extracted_Cert_${timestamp}.pem"
    extracted_chain="Extracted_Chain_${timestamp}.pem"
    extracted_priv="Extracted_PrivKey_${timestamp}.pem"
    ls -l
    echo
    read -r -p "PKCS#12 PFX file: " pfx_file
    echo
    echo "1) General Inspection"
    echo "2) Extract Cert PEM and Chain PEM"
    printf '3) Extract Priv Key %bCONFIDENTIAL DATA%b\n\n' "$red" "$colorreset"
    read -r -p "Selection: " selection

    case "$selection" in
        1) openssl pkcs12 -in "$pfx_file" -info -noout ;;
        2)
            openssl pkcs12 -in "$pfx_file" -clcerts -nokeys -out "$extracted_cert"
            openssl pkcs12 -in "$pfx_file" -cacerts -nokeys -out "$extracted_chain"
            msg_ok "Extracted Cert PEM file --> $extracted_cert"
            msg_ok "Extracted Chain PEM file --> $extracted_chain"
            ;;
        3)
            openssl pkcs12 -in "$pfx_file" -nocerts -out "$extracted_priv"
            msg_ok "Extracted Private Key PEM file --> $extracted_priv"
            msg_warn "CONFIDENTIAL DATA"
            ;;
        *) msg_err "Invalid selection." ;;
    esac
}

normalize_txt() {
    sed 's/^"//; s/"$//; s/\\"/"/g'
}

dcv_dns_txt_precheck() {
    msg_title "CHECK DNS TXT ENTRIES FOR DOMAIN VALIDATION"
    local txt_fqdn expected_token resolvers resolver out
    read -r -p "TXT Record FQDN (e.g. _dnsauth.example.com): " txt_fqdn
    read -r -p "Expected TXT token (optional - press Enter to skip): " expected_token
    echo

    if ! command -v dig >/dev/null 2>&1; then
        msg_err "dig not found. Install dnsutils/bind-utils."
        return
    fi

    resolvers="1.1.1.1 8.8.8.8"
    msg_warn "Querying public DNS resolvers..."
    echo
    for resolver in $resolvers; do
        printf '%b\n\n' "${purple}Resolver: $resolver${colorreset}"
        out=$(dig +time=2 +tries=1 +short TXT "$txt_fqdn" @"$resolver" 2>/dev/null | normalize_txt)
        if [ -z "$out" ]; then
            msg_err "No TXT record found (or not propagated yet)."
            echo
            continue
        fi
        echo "Found TXT:"
        echo "$out" | sed 's/^/ - /'
        echo
        if [ -n "$expected_token" ]; then
            if echo "$out" | grep -Fq "$expected_token"; then
                msg_ok "MATCH: expected token is present on resolver $resolver."
            else
                msg_err "NO MATCH: expected token not found on resolver $resolver."
            fi
        else
            msg_ok "OK: TXT record(s) present. No token provided for strict match."
        fi
        echo
    done
}

read_option() {
    local choice
    echo
    read -r -p "Enter choice: " choice
    case "$choice" in
        0) clear; show_help ;;
        1) clear; install_requirements ;;
        2) clear; create_rsa_key ;;
        3) clear; dump_key ;;
        4) clear; create_root_selfsigned ;;
        5) clear; create_csr ;;
        6) clear; issue_certificate ;;
        7) clear; create_pkcs12 ;;
        8) clear; dump_certificate_local ;;
        9) clear; dump_certificate_online ;;
        10) clear; verify_csr ;;
        11) clear; dump_pkcs12 ;;
        12) clear; dcv_dns_txt_precheck ;;
        99) printf '\n%b\n' "${green}Hack ${orange}the ${red}Planet ${colorreset}|m|"; exit 0 ;;
        *) clear; msg_err "Invalid option. Please try again." ;;
    esac
}

main() {
    case "${1:-}" in
        -h|--help|help)
            show_help
            exit 0
            ;;
    esac

    while true; do
        show_banner
        show_menu
        read_option
        echo
    done
}

main "$@"
