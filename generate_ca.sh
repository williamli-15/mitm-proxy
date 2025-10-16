#!/usr/bin/env bash
set -euo pipefail

mkdir -p ca

if [[ ! -f ca/ca.key ]]; then
  echo "[*] Generating CA private key (4096-bit RSA)..."
  openssl genrsa -out ca/ca.key 4096
  chmod 600 ca/ca.key
fi

if [[ ! -f ca/ca.crt ]]; then
  echo "[*] Generating CA root certificate (10 years)..."
  openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 3650 \
    -out ca/ca.crt -subj "/C=US/ST=CA/L=SanFrancisco/O=MITM Proxy/OU=Lab/CN=MITM Proxy Root CA"
  chmod 644 ca/ca.crt
fi

echo
echo "[*] CA created in ./ca"
echo "    - ca/ca.key (KEEP SECRET)"
echo "    - ca/ca.crt (import this into your browser/system trust store)"
echo
echo "Example (curl uses --cacert):"
echo "  curl --proxy http://127.0.0.1:8080 --cacert ca/ca.crt https://example.com/"
