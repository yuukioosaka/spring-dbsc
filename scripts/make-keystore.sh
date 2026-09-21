#!/bin/sh
# Generates the self-signed keystore the demo runs on.
#
# A self-signed cert is fine here: DBSC requires a secure context, which HTTPS on
# localhost satisfies, but it does not require a publicly trusted certificate.
# Your browser will show a warning the first time — accept it, or the __Host-
# cookies will not be stored and the flow will silently do nothing.
#
# SAN matters. Chromium treats an origin as trustworthy only if the certificate
# covers the exact hostname you type. "localhost" and "127.0.0.1" are different
# origins, so both are listed; using the machine's LAN IP instead will fail.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="$here/../src/demo/resources/keystore.p12"

if [ -f "$out" ]; then
  echo "keystore already exists: $out"
  echo "delete it first if you want to regenerate."
  exit 0
fi

keytool -genkeypair \
  -alias dbsc-demo \
  -keyalg EC \
  -groupname secp256r1 \
  -sigalg SHA256withECDSA \
  -storetype PKCS12 \
  -keystore "$out" \
  -storepass changeit \
  -validity 3650 \
  -dname "CN=dbsc-demo, O=Local Development, C=JP" \
  -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1"

echo
echo "wrote $out"
echo "run:  mvn -Pdemo -Dmaven.repo.local=.m2repo spring-boot:run"
echo "open: https://localhost:8443/login"
