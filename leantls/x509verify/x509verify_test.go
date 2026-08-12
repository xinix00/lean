package x509verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Twee soorten toetsen, en de tweede is de belangrijkste.
//
//  1. De ECHTE ketens van de hosts die onze vloot gebruikt, vastgelegd als
//     fixtures (12-08 opgehaald met openssl s_client). Die dekken wat er in het
//     wild gebeurt: ECDSA- én RSA-ketens, cross-signing, en een leaf met zes
//     wildcards in zijn SAN-lijst.
//  2. De AANVALSBATTERIJ: ketens die geweigerd MOETEN worden. Een validator die
//     alleen op goede ketens getest is, is niet getest — elk gat in deze
//     categorie is een verbinding die je denkt te hebben en niet hebt.
//
// De fixtures verlopen, dus de tijd waarop we valideren komt uit het leaf zelf
// (notBefore + een uur). Zo blijft deze test over drie maanden nog precies
// hetzelfde bewijzen, en de geldigheidscontrole zelf zit in de batterij.

func chainFrom(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, blk.Bytes)
		}
	}
}

// roots bouwt een pool uit de bundel in testdata, zodat deze test niet aan de
// trust store van de machine hangt.
func roots(t *testing.T) *x509.CertPool {
	t.Helper()
	b, err := os.ReadFile("../testdata/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		t.Fatal("geen roots uit cacert.pem")
	}
	return pool
}

func TestRealChains(t *testing.T) {
	files, _ := filepath.Glob("../testdata/chain-*.pem")
	if len(files) == 0 {
		t.Fatal("geen keten-fixtures")
	}
	pool := roots(t)
	for _, f := range files {
		host := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "chain-"), ".pem")
		t.Run(host, func(t *testing.T) {
			chain := chainFrom(t, f)
			leaf, err := x509.ParseCertificate(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			at := leaf.NotBefore.Add(time.Hour)

			v, err := ChainAt(pool, at)(chain, host)
			if err != nil {
				t.Fatalf("keten van %s afgewezen: %v", host, err)
			}
			if v == nil {
				t.Fatal("geen verifier terug")
			}
			// En een verkeerde naam moet dezelfde keten afwijzen.
			if _, err := ChainAt(pool, at)(chain, "attacker.example"); err == nil {
				t.Error("keten geldig verklaard voor een naam die er niet in staat")
			}
		})
	}
}

// De batterij: alles hieronder MOET falen.
func TestRejects(t *testing.T) {
	// Een eigen mini-PKI, zodat we de fouten kunnen máken.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newLeaf := func(tmpl *x509.Certificate, parent *x509.Certificate, pk any) [][]byte {
		t.Helper()
		if parent == nil {
			parent, pk = ca, caKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, pk)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{der}
	}
	base := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"good.example"},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}

	// verlopen
	exp := base()
	exp.NotBefore, exp.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)

	// nog niet geldig
	fut := base()
	fut.NotBefore, fut.NotAfter = time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)

	// een leaf die zichzelf CA verklaart en dan een tweede cert ondertekent:
	// het klassieke gat. Hier toetsen we de eerste helft — een leaf van een
	// onbekende uitgever.
	selfKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	selfTmpl := base()
	selfTmpl.Subject = pkix.Name{CommonName: "self"}
	// De naam MOET kloppen, anders faalt dit geval op de hostnaam en toetst het
	// niet wat het moet toetsen: dat een onbekende uitgever wordt geweigerd.
	selfTmpl.DNSNames = []string{"self"}
	selfDER, _ := x509.CreateCertificate(rand.Reader, selfTmpl, selfTmpl, &selfKey.PublicKey, selfKey)

	// verkeerde extended key usage (voor code signing uitgegeven)
	eku := base()
	eku.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}

	cases := []struct {
		name  string
		chain [][]byte
		host  string
		want  string
	}{
		{"verlopen", newLeaf(exp, nil, nil), "good.example", "expired"},
		{"nog niet geldig", newLeaf(fut, nil, nil), "good.example", "not yet valid"},
		{"onbekende uitgever", [][]byte{selfDER}, "self", "unknown authority"},
		{"verkeerde hostnaam", newLeaf(base(), nil, nil), "evil.example", "valid for"},
		{"wildcard te diep", newLeaf(wildcard(base()), nil, nil), "a.b.wild.example", "valid for"},
		{"wildcard op de bare naam", newLeaf(wildcard(base()), nil, nil), "wild.example", "valid for"},
		{"verkeerde EKU", newLeaf(eku, nil, nil), "good.example", ""},
		{"lege keten", nil, "good.example", "empty"},
		{"rommel in plaats van DER", [][]byte{{1, 2, 3}}, "good.example", "certificate 0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Chain(pool)(c.chain, c.host)
			if err == nil {
				t.Fatalf("GEACCEPTEERD, moest falen")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("melding %q bevat niet %q", err, c.want)
			}
			t.Logf("geweigerd: %v", err)
		})
	}
}

func wildcard(c *x509.Certificate) *x509.Certificate {
	c.DNSNames = []string{"*.wild.example"}
	return c
}

// De handtekening-verifier: een server mag niet kiezen welk algoritme bij zijn
// sleutel hoort. Dit toetst de twee verwisselingen die anders mogelijk zijn.
func TestVerifierAlgorithmMismatch(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)

	if err := verifierFor(&ec.PublicKey)(RSAPSSRSAeSHA256, []byte("x"), nil); err == nil {
		t.Error("RSA-code met een ECDSA-sleutel werd geaccepteerd")
	}
	if err := verifierFor(&rk.PublicKey)(ECDSASecp256r1SHA256, []byte("x"), nil); err == nil {
		t.Error("ECDSA-code met een RSA-sleutel werd geaccepteerd")
	}
	// Verkeerde curve bij de juiste soort.
	if err := verifierFor(&ec.PublicKey)(ECDSASecp384r1SHA384, []byte("x"), nil); err == nil {
		t.Error("P-384-code met een P-256-sleutel werd geaccepteerd")
	}
	// En een algoritme dat we niet aanbieden (PKCS#1v1.5, in 1.3 verboden voor
	// de handshake) mag nooit langskomen.
	if err := verifierFor(&rk.PublicKey)(0x0401, []byte("x"), nil); err == nil {
		t.Error("rsa_pkcs1_sha256 werd geaccepteerd in een TLS 1.3-handshake")
	}
}
