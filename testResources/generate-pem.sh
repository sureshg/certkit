#!/bin/sh
#
# Generates test PKI material (RSA, DSA, EC) for certkit unit tests.
#
# For each algorithm the script creates:
#   - A self-signed CA certificate
#   - A client key in both PKCS#8 and traditional (PKCS#1/SEC1) PEM formats
#   - A password-encrypted PKCS#8 client key
#   - Public keys (SPKI for all algorithms; PKCS#1 for RSA only)
#   - A CA-signed client certificate
#   - Composite PEM bundles (CA cert + client cert + key)
#   - A PKCS#12 (.p12) bundle
#
# Requires: OpenSSL 3.x+
# Usage: cd testResources && sh generate-pem.sh

set -eux

# ---------------------------------------------------------------------------
# Configuration — override any variable via the environment
# ---------------------------------------------------------------------------
PASSWORD="${PASSWORD:-certkit}"
SUBJECT_CA="${SUBJECT_CA:-/C=US/ST=CA/L=San Jose/O=CertKit/OU=RootCA}"
SUBJECT_CLIENT="${SUBJECT_CLIENT:-/C=US/ST=CA/L=San Jose/O=CertKit/OU=Server/CN=Test User}"
PKCS8_V1_ALGO="${PKCS8_V1_ALGO:-PBE-SHA1-3DES}"

# ---------------------------------------------------------------------------
# 1. CA private keys (unencrypted PKCS#8 PEM)
# ---------------------------------------------------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa.ca.key
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsaparam.pem
openssl genpkey -paramfile dsaparam.pem -out dsa.ca.key
openssl genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:prime256v1 -out ec.ca.key

# ---------------------------------------------------------------------------
# 2. Self-signed CA certificates
# ---------------------------------------------------------------------------
openssl req -new -x509 -days 9999 -subj "$SUBJECT_CA" -key rsa.ca.key -out rsa.ca.crt
openssl req -new -x509 -days 9999 -subj "$SUBJECT_CA" -key dsa.ca.key -out dsa.ca.crt
openssl req -new -x509 -days 9999 -subj "$SUBJECT_CA" -key ec.ca.key  -out ec.ca.crt

# ---------------------------------------------------------------------------
# 3. Client private keys
#    genpkey outputs PKCS#8 (BEGIN PRIVATE KEY).
#    pkey -traditional converts to the legacy format:
#      RSA → PKCS#1 (BEGIN RSA PRIVATE KEY)
#      DSA → (BEGIN DSA PRIVATE KEY)
#      EC  → SEC 1  (BEGIN EC PRIVATE KEY)
# ---------------------------------------------------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa.client.pkcs8.key
openssl pkey -traditional -in rsa.client.pkcs8.key -out rsa.client.pkcs1.key

openssl genpkey -paramfile dsaparam.pem -out dsa.client.pkcs8.key
openssl pkey -traditional -in dsa.client.pkcs8.key -out dsa.client.pkcs1.key

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ec.client.pkcs8.key
openssl pkey -traditional -in ec.client.pkcs8.key -out ec.client.pkcs1.key

# ---------------------------------------------------------------------------
# 4. Password-encrypted PKCS#8 client keys (BEGIN ENCRYPTED PRIVATE KEY)
#    Uses PKCS#5 v1 / PBES1 with PBE-SHA1-3DES by default.
# ---------------------------------------------------------------------------
openssl pkcs8 -topk8 -v1 "$PKCS8_V1_ALGO" -passout pass:"$PASSWORD" -in rsa.client.pkcs8.key -out rsa.client.pkcs8.key.encrypted
openssl pkcs8 -topk8 -v1 "$PKCS8_V1_ALGO" -passout pass:"$PASSWORD" -in dsa.client.pkcs8.key -out dsa.client.pkcs8.key.encrypted
openssl pkcs8 -topk8 -v1 "$PKCS8_V1_ALGO" -passout pass:"$PASSWORD" -in ec.client.pkcs8.key  -out ec.client.pkcs8.key.encrypted

# ---------------------------------------------------------------------------
# 5. Public keys
#    PKCS#1 / RSA-only format (BEGIN RSA PUBLIC KEY) — only RSA supports this.
#    SPKI / X.509 SubjectPublicKeyInfo (BEGIN PUBLIC KEY) — works for all.
# ---------------------------------------------------------------------------
openssl rsa  -in rsa.client.pkcs8.key -RSAPublicKey_out -out rsa.client.pkcs1.pub

openssl pkey -pubout -in rsa.client.pkcs8.key -out rsa.client.pkcs8.pub
openssl pkey -pubout -in dsa.client.pkcs8.key -out dsa.client.pkcs8.pub
openssl pkey -pubout -in ec.client.pkcs8.key  -out ec.client.pkcs8.pub

# ---------------------------------------------------------------------------
# 6. Client certificate signing requests (CSRs)
# ---------------------------------------------------------------------------
openssl req -new -subj "$SUBJECT_CLIENT" -key rsa.client.pkcs8.key -out rsa.client.csr
openssl req -new -subj "$SUBJECT_CLIENT" -key dsa.client.pkcs8.key -out dsa.client.csr
openssl req -new -subj "$SUBJECT_CLIENT" -key ec.client.pkcs8.key  -out ec.client.csr

# ---------------------------------------------------------------------------
# 7. CA-signed client certificates
# ---------------------------------------------------------------------------
openssl x509 -req -days 9999 -set_serial 01 -CA rsa.ca.crt -CAkey rsa.ca.key -in rsa.client.csr -out rsa.client.crt
openssl x509 -req -days 9999 -set_serial 01 -CA dsa.ca.crt -CAkey dsa.ca.key -in dsa.client.csr -out dsa.client.crt
openssl x509 -req -days 9999 -set_serial 01 -CA ec.ca.crt  -CAkey ec.ca.key -in ec.client.csr  -out ec.client.crt

# ---------------------------------------------------------------------------
# 8. Composite PEM bundles (CA cert + client cert + private key)
#    Unencrypted bundles use the traditional key; encrypted bundles use PKCS#8.
# ---------------------------------------------------------------------------
cat rsa.ca.crt rsa.client.crt rsa.client.pkcs1.key > rsa.client.pkcs1.pem
cat dsa.ca.crt dsa.client.crt dsa.client.pkcs1.key > dsa.client.pkcs1.pem
cat ec.ca.crt  ec.client.crt  ec.client.pkcs1.key  > ec.client.pkcs1.pem

cat rsa.ca.crt rsa.client.crt rsa.client.pkcs8.key.encrypted > rsa.client.pkcs8.pem.encrypted
cat dsa.ca.crt dsa.client.crt dsa.client.pkcs8.key.encrypted > dsa.client.pkcs8.pem.encrypted
cat ec.ca.crt  ec.client.crt  ec.client.pkcs8.key.encrypted  > ec.client.pkcs8.pem.encrypted

# ---------------------------------------------------------------------------
# 9. PKCS#12 bundles (client key + client cert + CA cert chain)
# ---------------------------------------------------------------------------
openssl pkcs12 -export -inkey rsa.client.pkcs8.key -in rsa.client.crt -certfile rsa.ca.crt -passout pass:"$PASSWORD" -out rsa.client.p12
openssl pkcs12 -export -inkey dsa.client.pkcs8.key -in dsa.client.crt -certfile dsa.ca.crt -passout pass:"$PASSWORD" -out dsa.client.p12
openssl pkcs12 -export -inkey ec.client.pkcs8.key  -in ec.client.crt  -certfile ec.ca.crt  -passout pass:"$PASSWORD" -out ec.client.p12

# ---------------------------------------------------------------------------
# 10. Cleanup intermediate files that are not needed by the tests
# ---------------------------------------------------------------------------
rm rsa.ca.key dsa.ca.key ec.ca.key dsaparam.pem
rm rsa.client.csr dsa.client.csr ec.client.csr