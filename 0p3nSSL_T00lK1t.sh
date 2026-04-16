#!/bin/sh

# OpenSSL toolkit v2
# by Futurisiko

# Text color declaration
colorreset=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
orange=$(tput setaf 3)
purple=$(tput setaf 5)

# Banner
show_banner() {
#    echo "${colorreset}\n--------------------"
#    echo "\n${red}  0p3nSSL T00lK1t   ${colorreset}"
#    echo "${colorreset}\n--------------------"
#}
echo "${purple}
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
${colorreset}"
}


# Menu
show_menu() {
    echo "\n${green}Menu :${colorreset}"
    echo "\n${orange}Utility${colorreset}"
    echo "1) Install Requirements"
    echo "\n${orange}Key Tools${colorreset}"
    echo "2) Create a RSA Private Key AES/256 Encrypted"
    echo "3) Dump Private or Public Key (PEM) Data"
    echo "\n${orange}Certificate Creation Tools${colorreset}"
    echo "4) Create Root Self-Signed Certificate"
    echo "5) Create Generic CSR/PKCS#10 Request"
    echo "6) Issue Certificate with CSR and Target CA"
    echo "7) Create a PKCS#12 with PrivKey,Cert and CertChain"
    echo "\n${orange}Certificate Dump Tools${colorreset}"
    echo "8) Dump Certificate Data Locally"
    echo "9) Verify and Dump Certificate Data Online"
    echo "10) Verify and Dump CSR/PKCS#10 Data Locally"
    echo "11) Verify and Dump PKCS#12 Data Locally"
	echo "\n${orange}Validations Utility${colorreset}"
	echo "12) Check DNS TXT Entries for Domain Validation"
    echo "\n${orange}99) Exit${colorreset}"
}

# 

# Choise handler and Functions
read_option() {
    local choice
    echo " "
    read -p "Enter choice : " choice
    case $choice in
        1)
            clear
            echo "\n${red}INSTALLING REQUIREMENTS${colorreset}\n"
            sudo apt update
            sudo apt install openssl dnsutils -y
            ;;
        2)
            clear
            echo "\n${red}CREATING PRIVATE RSA ENCRYPTED KEY${colorreset}\n"
            timestamp=$(date +"%Y%m%d_%H%M%S")
            filename="priv_key_${timestamp}.pem"
            echo "1) RSA 2048 (standard)"
            echo "2) RSA 4096 (root)\n"
            read cryptchoise
            case $cryptchoise in
                1)
                    # RSA key 2048 in PEM
                    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -out $filename
                    echo "\nKey generated --> ${green}$filename${colorreset}"
                ;;
                2)
                    # RSA key 4096 in PEM
                    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes-256-cbc -out $filename
                    echo "\nKey generated --> ${green}$filename${colorreset}"
                ;;
            esac
            ;;
        3)
            clear
            echo "\n${red}DUMP KEY DATA${colorreset}\n"
            ls -l
            echo " "
            read -p "Private Key PEM file : " varprivpem
            echo "\n1) Dump Public Key"
            echo "2) Dump Private Key (${red}CONFIDENTIAL DATA${colorreset})\n"
            read secondchoise
            echo " "
            case $secondchoise in
                1)
                    openssl pkey -in $varprivpem -pubout
                    ;;
                2)
                    openssl pkey -in $varprivpem -noout -text
                    ;;
            esac
            ;;
        4)
            clear
            echo "\n${red}CREATE ROOT SELF-SIGNED CERTIFICATE/CA${colorreset}\n"
            timestamp=$(date +"%Y%m%d_%H%M%S")
            rootselfname="root_cert_selfsigned_${timestamp}.pem"
            ls -l
            echo " "
            read -p "Private Key file (better to use RSA 4096): " varrootselfsigned
            read -p "Common Name (e.g. Lab Root CA) : " varcommonnametwo
            read -p "Organization (e.g. Lab CA) : " varorganizationtwo
            read -p "State (e.g. US) : " varstatetwo
            read -p "Days of Validity (e.g. 365): " rootvaliditydays
            # self-signed certificate/CA
            openssl req -x509 -new -key $varrootselfsigned -sha256 -days $rootvaliditydays -out $rootselfname -subj "/C=$varstatetwo/O=$varorganizationtwo/CN=$varcommonnametwo"
            echo "\nRoot Cert Self-Signed generated --> ${green}$rootselfname${colorreset}"
            ;;
        5)
            clear
            echo "\n${red}CREATING CSR/PKCS#10${colorreset}\n"
            timestamp=$(date +"%Y%m%d_%H%M%S")
            reqname="csr_request_${timestamp}.csr"
            ls -l
            echo " "
            read -p "Private Key file : " varprivkey
            read -p "Common Name (e.g. www.example.com) : " varcommonname
            read -p "Organization (e.g. Example) : " varorganization
            read -p "State (e.g. US) : " varstate
            echo "Additional Text"
            echo "e.g. subjectAltName=DNS:www.example.local,DNS:example.local,IP:10.0.0.1,email:admin@example.com,URI:https://example.com"
            read varaddtext
            # CSR PKCS#10 creation
            openssl req -new -key $varprivkey -out $reqname -subj "/C=$varstate/O=$varorganization/CN=$varcommonname" -addext "$varaddtext"
            echo "\nRequest generated --> ${green}$reqname${colorreset}"
            ;;
        6)
            clear
            echo "\n${red}ISSUE CERTIFICATE WITH CSR AND LOCAL/TARGET CA${colorreset}\n"
            ls -l
            echo " "
            timestamp=$(date +"%Y%m%d_%H%M%S")
            issuedcertname="signed_issued_cert_${timestamp}.pem"
            read -p "CSR file : " csrfiletobesigned
            read -p "Root CA Cert file : " rootcacertfile
            read -p "Root CA Key file : " rootcakeyfile
            read -p "Days of Validity (e.g. 365): " certvaliditydays
            # signing CSR with local CA
            openssl x509 -req -in $csrfiletobesigned -CA $rootcacertfile -CAkey $rootcakeyfile -CAcreateserial -out $issuedcertname -days $certvaliditydays -sha256 -copy_extensions copyall
            echo "\nIssued Self-Signed Certificate generated --> ${green}$issuedcertname${colorreset}"
            echo "\nVerifing Issued Certificate.."
            openssl verify -CAfile $rootcacertfile $issuedcertname
            ;;
		7)
            clear
            echo "\n${red}CREATE PKCS#12${colorreset}\n"
            ls -l
            timestamp=$(date +"%Y%m%d_%H%M%S")
            issuedpkcs12name="PKCS12_${timestamp}.pfx"
            echo " "
            read -p "Client PEM Private Key file : " varprivpkcs12
            read -p "Client PEM Certificate file : " varcertpkcs12
            read -p "PEM Certificate Chain file related : " varintermediatechain
            # creation of pkcs#12
            openssl pkcs12 -export -out $issuedpkcs12name -inkey $varprivpkcs12 -in $varcertpkcs12 -certfile $varintermediatechain -name "tls-cert"
            echo "\nPKCS#12 generated --> ${green}$issuedpkcs12name${colorreset}"
            ;;
        8)
            clear
            echo "\n${red}DUMP CERTIFICATE DATA${colorreset}\n"
            ls -l
            echo " "
            read -p "Certificate CRT/PEM file : " varcertificatecrtpem
            echo "\n1) Dump just data/subject/issuer"
            echo "2) Dump ALL Certificate Data\n"
            read thirdchoise
            echo " "
            case $thirdchoise in
                1)
                    # partial dump
                    openssl x509 -in $varcertificatecrtpem -noout -subject -issuer -dates
                    ;;
                2)
                    # full dump
                    openssl x509 -in $varcertificatecrtpem -noout -text
                    ;;
            esac
            ;;
        9)
            clear
            echo "\n${red}DUMP ONLINE CERTIFICATE DATA${colorreset}\n"
            read -p "Site to be checked (e.g. google.com) : " sitetarget
            read -p "Service port exposed (e.g. 443) : " siteporttarget
            echo " "
            openssl s_client -connect $sitetarget:$siteporttarget </dev/null 2>/dev/null | openssl x509 -text
            echo " "
            read -p "Do you want to save it into a file or check it via OCSP ? ( Yes / No ) : " savelocalfile
            case $savelocalfile in
                Y|y|Yes|yes)
                    timestamp=$(date +"%Y%m%d_%H%M%S")
                    targetcertsavedlocally="Cert_Dumped_${timestamp}.pem"
                    openssl s_client -connect $sitetarget:$siteporttarget </dev/null 2>/dev/null | openssl x509 -outform PEM > $targetcertsavedlocally
                    echo "\nCertificate saved --> ${green}$targetcertsavedlocally${colorreset}\n"
                    read -p "Do you want to check Certificate state via OCSP ? ( Yes / No ) : " checkcertificatestate
                    case $checkcertificatestate in
                        Y|y|Yes|yes)
                            OCSPURL=$(openssl s_client -connect $sitetarget:$siteporttarget </dev/null 2>/dev/null | openssl x509 -text | awk -F'URI:' '/OCSP - URI:/{print $2; exit}')
                            CAISSUERURL=$(openssl s_client -connect $sitetarget:$siteporttarget </dev/null 2>/dev/null | openssl x509 -text | awk -F'URI:' '/CA Issuers - URI:/{print $2; exit}')
                            timestamp=$(date +"%Y%m%d_%H%M%S")
                            ISSUERCERTDOWNLOADED="Issuer_for_OCSP_query_${timestamp}"
                            curl -L -o "$ISSUERCERTDOWNLOADED.cer" "$CAISSUERURL" 2>/dev/null
                            openssl x509 -in "$ISSUERCERTDOWNLOADED.cer" -inform DER -out "$ISSUERCERTDOWNLOADED.pem"
                            echo "\nIssuer Certificate CER --> ${green}$ISSUERCERTDOWNLOADED.cer${colorreset}"
                            echo "Issuer Certificate PEM --> ${green}$ISSUERCERTDOWNLOADED.pem${colorreset}\n"
                            openssl ocsp -issuer "$ISSUERCERTDOWNLOADED.pem" -cert "$targetcertsavedlocally" -url "$OCSPURL" -resp_text
                        ;;
                        *)
                            echo "\nOk |m|"
                        ;;
                    esac
                ;;
                *)
                    echo "\nOk |m|"
                ;;
            esac
            ;;
        10)
            clear
            echo "\n${red}CSR VERIFICATION${colorreset}\n"
            ls -l
            echo " "
            read -p "CSR file : " varvalcsr
            echo " "
            # check validity
            openssl req -in $varvalcsr -noout -verify
            echo "\n${red}INSPECTING CSR${colorreset}\n"
            # CSR inspection
            openssl req -in $varvalcsr -noout -text
            ;;
        11)
            clear
            echo "\n${red}DUMP PKCS#12 DATA${colorreset}\n"
            ls -l
            timestamp=$(date +"%Y%m%d_%H%M%S")
            extractedcert="Extracted_Cert_${timestamp}.pem"
            extractedchain="Extracted_Chain_${timestamp}.pem"
            extractedprivkey="Extracted_PrivKey_${timestamp}.pem"
            echo " "
            read -p "PKCS#12 PFX file : " varpkcs12pem
            echo "\n1) General Inspection"
            echo "2) Extract Cert PEM and Chain PEM"
            echo "3) Extract Priv Key ${red}CONFIDENTIAL DATA${colorreset}\n"
            read fourthchoise
            echo " "
            case $fourthchoise in
                1)
                    # general inspection
                    openssl pkcs12 -in $varpkcs12pem -info -noout
                    ;;
                2)
                    # Cert and Chain extraction
                    openssl pkcs12 -in $varpkcs12pem -clcerts -nokeys -out $extractedcert
                    openssl pkcs12 -in $varpkcs12pem -cacerts -nokeys -out $extractedchain
                    echo "\nExtracted Cert PEM file --> ${green}$extractedcert${colorreset}"
                    echo "Extracted Chain PEM file --> ${green}$extractedchain${colorreset}"
                    ;;
                3)
                    # Priv Key extraction
                    openssl pkcs12 -in $varpkcs12pem -nocerts -out $extractedprivkey
                    echo "\nExtracted Private Key PEM file --> ${green}$extractedprivkey${colorreset}"
                    echo "${red}CONFIDENTIAL DATA${colorreset}"
                    ;;
            esac
            ;;
		12)
			clear
			echo "\n${red}CHECK DNS TXT ENTRIES FOR DOMAIN VALIDATION${colorreset}\n"
			read -p "TXT Record FQDN (e.g. _dnsauth.example.com) : " txt_fqdn
			read -p "Expected TXT token (optional - press Enter to skip) : " expected_token
			echo " "
			echo "${orange}Querying public DNS resolvers...${colorreset}"
			echo " "

			# Resolver list (public + system default)
			resolvers="1.1.1.1 8.8.8.8"

			# Helper: normalize TXT output (strip quotes)
			normalize_txt() {
				sed 's/^"//; s/"$//; s/\\"/"/g'
			}

			if command -v dig >/dev/null 2>&1; then
				for r in $resolvers; do
					echo "${purple}Resolver: $r${colorreset}\n"
					out=$(dig +time=2 +tries=1 +short TXT "$txt_fqdn" @"$r" 2>/dev/null | normalize_txt)
					if [ -z "$out" ]; then
						echo "${red}No TXT record found (or not propagated yet).${colorreset}\n"
						continue
					fi
					echo "Found TXT:"
					echo "$out" | sed 's/^/  - /'
					echo " "
					if [ -n "$expected_token" ]; then
						echo "$out" | grep -Fq "$expected_token"
						if [ $? -eq 0 ]; then
							echo "${green}MATCH: expected token is present on resolver $r.${colorreset}\n"
						else
							echo "${red}NO MATCH: expected token not found on resolver $r.${colorreset}\n"
						fi
					else
						echo "${green}OK: TXT record(s) present. (No token provided for strict match)${colorreset}\n"
					fi
				done
			else
				echo "\n${red}DIG not found on this system.${colorreset}"
				echo "${orange}Install requirements.${colorreset}\n"
			fi
			;;
        99)
            echo "\n${green}Hack ${orange}the ${red}Planet ${colorreset}|m|\n"
            exit 0 
			;;
        *)
            clear
            echo "\n${red}Invalid option. ${colorreset}Please try again."
            ;;
    esac
}

# Main loop
while true; do
    show_banner
    show_menu
    read_option
    echo " "
done
