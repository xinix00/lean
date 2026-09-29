#!/bin/sh
# Maakt de testketens voor x509 (leantls/src/x509/tests.rs) opnieuw aan.
#
# De sleutels staan erbij: het zijn testsleutels zonder waarde, en de
# goserver-interop (testdata/goserver, modi x509ecdsa en x509rsa) tekent er
# de CertificateVerify mee. Datums liggen vast, zodat de tests een vaste
# `now` kunnen gebruiken en dit script niet elk jaar opnieuw hoeft.
#
#   ecdsa-*   P-256: root -> inter (pathlen 0) -> leaf (leantls.test)
#   rsa-*     RSA-2048, zelfde vorm, handtekeningen sha256WithRSAEncryption
#   nocs-*    tussen-CA zonder keyCertSign in KeyUsage, plus blad
#   notca-*   tussen-CA met cA=FALSE, plus blad
#   deep-*    tweede tussen-CA onder ecdsa-inter (schendt pathlen 0), plus blad
#   eku-leaf  blad met alleen codeSigning
#   nc-*      tussen-CA met nameConstraints, plus blad
#   evil-root zelfde naam als ecdsa-root, andere sleutel
#
# Vereist OpenSSL 3.4 of nieuwer (-not_before/-not_after).
set -eu
cd "$(dirname "$0")"

ROOT_FROM=20260101000000Z
ROOT_TO=20460101000000Z
LEAF_FROM=20260601000000Z
LEAF_TO=20270601000000Z

cat > ext.cnf <<'CNF'
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[inter]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[inter_open]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[nocs]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[notca]
basicConstraints = critical, CA:FALSE
keyUsage = critical, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[nc]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
nameConstraints = critical, permitted;DNS:leantls.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:leantls.test, DNS:*.wild.leantls.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[eku]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectAltName = DNS:leantls.test
authorityKeyIdentifier = keyid
CNF

key() { # naam soort
    case $2 in
    ec) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" ;;
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null ;;
    esac
}

root() { # naam cn soort
    key "$1" "$3"
    openssl req -x509 -new -key "$1.key" -subj "/O=leantls test/CN=$2" \
        -not_before $ROOT_FROM -not_after $ROOT_TO -sha256 \
        -config ext.cnf -extensions root -set_serial 1 -out "$1.pem"
    openssl x509 -in "$1.pem" -outform DER -out "$1.der"
}

sign() { # naam cn soort ca sectie serial van tot
    key "$1" "$3"
    openssl req -new -key "$1.key" -subj "/O=leantls test/CN=$2" -out "$1.csr"
    openssl x509 -req -in "$1.csr" -CA "$4.pem" -CAkey "$4.key" -sha256 \
        -not_before "$7" -not_after "$8" -set_serial "$6" \
        -extfile ext.cnf -extensions "$5" -out "$1.pem"
    openssl x509 -in "$1.pem" -outform DER -out "$1.der"
    rm "$1.csr"
}

root ecdsa-root "ECDSA Root" ec
sign ecdsa-inter "ECDSA Inter" ec ecdsa-root inter 2 $ROOT_FROM 20360101000000Z
sign ecdsa-leaf leantls.test ec ecdsa-inter leaf 3 $LEAF_FROM $LEAF_TO

root rsa-root "RSA Root" rsa
sign rsa-inter "RSA Inter" rsa rsa-root inter 2 $ROOT_FROM 20360101000000Z
sign rsa-leaf leantls.test rsa rsa-inter leaf 3 $LEAF_FROM $LEAF_TO

sign nocs-inter "No CertSign" ec ecdsa-root nocs 4 $ROOT_FROM 20360101000000Z
sign nocs-leaf leantls.test ec nocs-inter leaf 5 $LEAF_FROM $LEAF_TO

sign notca-inter "Not A CA" ec ecdsa-root notca 6 $ROOT_FROM 20360101000000Z
sign notca-leaf leantls.test ec notca-inter leaf 7 $LEAF_FROM $LEAF_TO

sign deep-inter "Deep Inter" ec ecdsa-inter inter_open 8 $ROOT_FROM 20360101000000Z
sign deep-leaf leantls.test ec deep-inter leaf 9 $LEAF_FROM $LEAF_TO

sign eku-leaf leantls.test ec ecdsa-inter eku 10 $LEAF_FROM $LEAF_TO

sign nc-inter "Constrained" ec ecdsa-root nc 11 $ROOT_FROM 20360101000000Z
sign nc-leaf leantls.test ec nc-inter leaf 12 $LEAF_FROM $LEAF_TO

root evil-root "ECDSA Root" ec
rm -f ext.cnf *.srl *.pem

# Een CertificateVerify-achtige handtekening per bladsleutel, voor
# verify_signature: ECDSA P-256/SHA-256 en RSA-PSS/SHA-256 met zout = 32.
printf 'leantls certificate verify' > cv.msg
openssl dgst -sha256 -sign ecdsa-leaf.key -out cv-ecdsa.sig cv.msg
openssl dgst -sha256 -sign rsa-leaf.key -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:digest -out cv-rsa-pss.sig cv.msg
