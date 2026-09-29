// Package x509verify provides ordinary HTTPS trust for leantls by validating a
// certificate chain through crypto/x509. It is separate so pinned-key users do
// not link PKI code.
//
// Measured for the same tamago/riscv64 download (`-w -T 0x84010000`,
// 2026-08-12):
//
//	net/http + crypto/tls ...................... 5.53 MB
//	leanhttp + crypto/tls ...................... 4.43 MB (-1.10)
//	leanhttp + leantls + this package .......... 3.80 MB (-1.73)
//
// The whole stack saves 1.73 MB: 1.10 MB from leanhttp and 0.63 MB from leantls
// plus this package. A crypto/tls-only baseline understated the benefit because
// real downloads also need net/http. Custom X.509 validation saved only about
// 0.2 MB while reimplementing the most error-prone part of TLS, so this package
// deliberately uses the standard verifier.
//
// # Usage
//
//	// A system trust store supplies roots. On bare metal, import
//	// golang.org/x/crypto/x509roots/fallback or construct a pool.
//	conn, err := leantls.Dial("tcp", "github.com:443", &leantls.Config{
//	    ServerName:          "github.com",
//	    VerifyPeer:          x509verify.Chain(nil),
//	    SignatureAlgorithms: x509verify.SignatureAlgorithms,
//	})
package x509verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// TLS server-signature codes allowed for TLS 1.3 CertificateVerify
// (RFC 8446 §4.2.3). PKCS#1v1.5 is valid only inside certificates, not the
// handshake.
const (
	ECDSASecp256r1SHA256 uint16 = 0x0403
	ECDSASecp384r1SHA384 uint16 = 0x0503
	ECDSASecp521r1SHA512 uint16 = 0x0603
	RSAPSSRSAeSHA256     uint16 = 0x0804
	RSAPSSRSAeSHA384     uint16 = 0x0805
	RSAPSSRSAeSHA512     uint16 = 0x0806
	Ed25519              uint16 = 0x0807
)

// SignatureAlgorithms lists every algorithm this package verifies, preferred
// with shorter, cheaper ECDSA first. Offer no unverifiable algorithm: the server
// chooses directly from this list.
var SignatureAlgorithms = []uint16{
	ECDSASecp256r1SHA256,
	ECDSASecp384r1SHA384,
	ECDSASecp521r1SHA512,
	RSAPSSRSAeSHA256,
	RSAPSSRSAeSHA384,
	RSAPSSRSAeSHA512,
	Ed25519,
}

// Chain returns a leantls Config.VerifyPeer-compatible verifier using
// crypto/x509 and roots. Nil roots selects the system trust store, including a
// bare-metal store installed by golang.org/x/crypto/x509roots/fallback. The
// structural function type avoids importing leantls.
func Chain(roots *x509.CertPool) func(certs [][]byte, serverName string) (func(uint16, []byte, []byte) error, error) {
	return chainAt(roots, nil)
}

// ChainAt is Chain with a fixed validation time. It supports pre-NTP nodes whose
// 1970 clock would reject every certificate; callers explicitly assume the
// security consequences of overriding validity time.
func ChainAt(roots *x509.CertPool, at time.Time) func(certs [][]byte, serverName string) (func(uint16, []byte, []byte) error, error) {
	return chainAt(roots, &at)
}

func chainAt(roots *x509.CertPool, at *time.Time) func([][]byte, string) (func(uint16, []byte, []byte) error, error) {
	return func(certs [][]byte, serverName string) (func(uint16, []byte, []byte) error, error) {
		if len(certs) == 0 {
			return nil, errors.New("x509verify: empty certificate chain")
		}
		parsed := make([]*x509.Certificate, len(certs))
		for i, der := range certs {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("x509verify: certificate %d: %w", i, err)
			}
			parsed[i] = c
		}
		// The wire chain supplies candidates; crypto/x509 builds the path itself.
		// Cross-signing makes blindly following server order incorrect.
		inter := x509.NewCertPool()
		for _, c := range parsed[1:] {
			inter.AddCert(c)
		}
		opts := x509.VerifyOptions{
			DNSName:       serverName,
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if at != nil {
			opts.CurrentTime = *at
		}
		if _, err := parsed[0].Verify(opts); err != nil {
			return nil, err
		}
		return verifierFor(parsed[0].PublicKey), nil
	}
}

// verifierFor checks CertificateVerify with the leaf key. The selected
// algorithm, hash, and certificate key type must all agree.
func verifierFor(pub crypto.PublicKey) func(uint16, []byte, []byte) error {
	return func(alg uint16, signed, sig []byte) error {
		if alg == Ed25519 {
			k, ok := pub.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("x509verify: server chose Ed25519 but its certificate holds a %T", pub)
			}
			if !ed25519.Verify(k, signed, sig) {
				return errors.New("x509verify: CertificateVerify signature is invalid")
			}
			return nil
		}

		h, err := hashFor(alg)
		if err != nil {
			return err
		}
		sum := digest(h, signed)

		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if !isECDSA(alg) {
				return fmt.Errorf("x509verify: server chose %#04x but its certificate holds an ECDSA key", alg)
			}
			// The selected ECDSA code must match the certificate's curve.
			if want := curveFor(alg); k.Curve.Params().Name != want {
				return fmt.Errorf("x509verify: server chose %#04x (%s) but its key is on %s",
					alg, want, k.Curve.Params().Name)
			}
			if !ecdsa.VerifyASN1(k, sum, sig) {
				return errors.New("x509verify: CertificateVerify signature is invalid")
			}
		case *rsa.PublicKey:
			if isECDSA(alg) {
				return fmt.Errorf("x509verify: server chose %#04x but its certificate holds an RSA key", alg)
			}
			// TLS 1.3 requires PSS with salt length equal to the hash (§4.2.3);
			// PKCS#1v1.5 is forbidden in the handshake.
			if err := rsa.VerifyPSS(k, h, sum, sig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       h,
			}); err != nil {
				return errors.New("x509verify: CertificateVerify signature is invalid")
			}
		default:
			return fmt.Errorf("x509verify: cannot verify a signature with a %T key", pub)
		}
		return nil
	}
}

func hashFor(alg uint16) (crypto.Hash, error) {
	switch alg {
	case ECDSASecp256r1SHA256, RSAPSSRSAeSHA256:
		return crypto.SHA256, nil
	case ECDSASecp384r1SHA384, RSAPSSRSAeSHA384:
		return crypto.SHA384, nil
	case ECDSASecp521r1SHA512, RSAPSSRSAeSHA512:
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("x509verify: server chose signature algorithm %#04x, which this package "+
		"does not offer (see SignatureAlgorithms)", alg)
}

func digest(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA256:
		s := sha256.Sum256(b)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	default:
		s := sha512.Sum512(b)
		return s[:]
	}
}

func isECDSA(alg uint16) bool {
	return alg == ECDSASecp256r1SHA256 || alg == ECDSASecp384r1SHA384 || alg == ECDSASecp521r1SHA512
}

func curveFor(alg uint16) string {
	switch alg {
	case ECDSASecp256r1SHA256:
		return "P-256"
	case ECDSASecp384r1SHA384:
		return "P-384"
	default:
		return "P-521"
	}
}
