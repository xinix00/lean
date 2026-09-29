// Command goserver is the crypto/tls peer for the leantls interop tests.
//
// It prints one line, "<addr> <hex key>", and then serves until killed. The
// key is the server's Ed25519 key (pinned modes) or the CA's key (chain mode).
//
//	echo13     TLS 1.3 only, Ed25519 self-signed, echo
//	echo12     TLS 1.2 only, Ed25519 self-signed, echo
//	discard13  TLS 1.3, reads until EOF, then prints "result: <err|EOF>"
//	chain13    TLS 1.3, Ed25519 leaf for leantls.test signed by an Ed25519 CA
//	ecdsa13    TLS 1.3, ECDSA P-256 self-signed (not an Ed25519 peer)
//	x509ecdsa  TLS 1.3, the P-256 chain from <dir> (testdata/chain): leaf + inter
//	x509rsa    TLS 1.3, the RSA-2048 chain from <dir>; signs CertificateVerify with PSS
//
// The x509 modes take the chain directory as a second argument and print a
// zero key: the caller trusts the root from the same directory.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

func cert(tmpl, parent *x509.Certificate, pub, signer any) []byte {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	return der
}

func template(serial int64, cn string, ca bool) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"leantls.test"},
	}
	if ca {
		t.IsCA = true
		t.KeyUsage = x509.KeyUsageCertSign
		t.BasicConstraintsValid = true
		t.DNSNames = nil
	}
	return t
}

func main() {
	mode := os.Args[1]
	var chain [][]byte
	var priv crypto.PrivateKey
	var shown []byte
	minV, maxV := uint16(tls.VersionTLS13), uint16(tls.VersionTLS13)

	switch mode {
	case "echo13", "echo12", "discard13":
		pub, k, _ := ed25519.GenerateKey(rand.Reader)
		t := template(1, "leantls-test", false)
		chain, priv, shown = [][]byte{cert(t, t, pub, k)}, k, pub
		if mode == "echo12" {
			minV, maxV = tls.VersionTLS12, tls.VersionTLS12
		}
	case "chain13":
		caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
		caT := template(1, "leantls test CA", true)
		caDER := cert(caT, caT, caPub, caKey)
		ca, _ := x509.ParseCertificate(caDER)
		pub, k, _ := ed25519.GenerateKey(rand.Reader)
		leaf := cert(template(2, "leantls.test", false), ca, pub, caKey)
		chain, priv, shown = [][]byte{leaf, caDER}, k, caPub
	case "ecdsa13":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		t := template(1, "leantls-test", false)
		chain, priv, shown = [][]byte{cert(t, t, &k.PublicKey, k)}, k, make([]byte, 32)
	case "x509ecdsa", "x509rsa":
		dir, prefix := os.Args[2], "ecdsa"
		if mode == "x509rsa" {
			prefix = "rsa"
		}
		read := func(name string) []byte {
			b, err := os.ReadFile(dir + "/" + prefix + "-" + name)
			if err != nil {
				panic(err)
			}
			return b
		}
		blk, _ := pem.Decode(read("leaf.key"))
		if blk == nil {
			panic("no PEM in " + prefix + "-leaf.key")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			panic(err)
		}
		chain, priv, shown = [][]byte{read("leaf.der"), read("inter.der")}, k, make([]byte, 32)
	default:
		panic("unknown mode " + mode)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: priv}},
		MinVersion:   minV,
		MaxVersion:   maxV,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s %s\n", ln.Addr(), hex.EncodeToString(shown))
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			if mode == "discard13" {
				_, err := io.Copy(io.Discard, c)
				if err == nil || errors.Is(err, io.EOF) {
					fmt.Println("result: EOF")
				} else {
					fmt.Printf("result: %v\n", err)
				}
				return
			}
			io.Copy(c, c)
		}(c)
	}
}
