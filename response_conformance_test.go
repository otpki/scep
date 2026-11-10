// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package scep_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

func TestCertRepResponseAlgorithmsAndNonces(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SCEP test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	request := &scep.PKIMessage{TransactionID: "test", SenderNonce: make([]byte, 16)}
	for _, tc := range []struct {
		name         string
		makeResponse func() (*scep.PKIMessage, error)
		digest       asn1.ObjectIdentifier
	}{
		{"pending default", func() (*scep.PKIMessage, error) { return request.Pending(cert, key) }, pkcs7.OIDDigestAlgorithmSHA1},
		{"pending SHA-256", func() (*scep.PKIMessage, error) {
			return request.Pending(cert, key, scep.WithResponseDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256))
		}, pkcs7.OIDDigestAlgorithmSHA256},
		{"pending SHA-1", func() (*scep.PKIMessage, error) {
			return request.Pending(cert, key, scep.WithResponseDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1))
		}, pkcs7.OIDDigestAlgorithmSHA1},
		{"pending default again", func() (*scep.PKIMessage, error) { return request.Pending(cert, key) }, pkcs7.OIDDigestAlgorithmSHA1},
		{"failure default", func() (*scep.PKIMessage, error) { return request.Fail(cert, key, scep.BadAlg) }, pkcs7.OIDDigestAlgorithmSHA1},
		{"failure SHA-256", func() (*scep.PKIMessage, error) {
			return request.Fail(cert, key, scep.BadAlg, scep.WithResponseDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256))
		}, pkcs7.OIDDigestAlgorithmSHA256},
		{"failure SHA-1", func() (*scep.PKIMessage, error) {
			return request.Fail(cert, key, scep.BadAlg, scep.WithResponseDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1))
		}, pkcs7.OIDDigestAlgorithmSHA1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := tc.makeResponse()
			if err != nil {
				t.Fatal(err)
			}
			p7, err := pkcs7.Parse(response.Raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(p7.Signers) != 1 || !p7.Signers[0].DigestAlgorithm.Algorithm.Equal(tc.digest) {
				t.Fatalf("CertRep digest = %v, want %v", p7.Signers[0].DigestAlgorithm.Algorithm, tc.digest)
			}
			var sender, recipient []byte
			if err := p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}, &sender); err != nil {
				t.Fatal(err)
			}
			if err := p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}, &recipient); err != nil {
				t.Fatal(err)
			}
			if len(sender) != 16 || bytes.Equal(sender, request.SenderNonce) || !bytes.Equal(recipient, request.SenderNonce) {
				t.Fatal("CertRep nonce correlation is invalid")
			}
			if response.PKIStatus == scep.FAILURE && response.FailInfo != scep.BadAlg {
				t.Fatalf("failure code = %s, want %s", response.FailInfo, scep.BadAlg)
			}
		})
	}
}

func TestSuccessResponseDigestOption(t *testing.T) {
	request := testParsePKIMessage(t, readTestFile(t, "PKCSReq.der"))
	caCert, caKey := loadCACredentials(t)
	if err := request.DecryptPKIEnvelope(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		options []scep.ResponseOption
		digest  asn1.ObjectIdentifier
	}{
		{"default", nil, pkcs7.OIDDigestAlgorithmSHA1},
		{"SHA-256", []scep.ResponseOption{scep.WithResponseDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)}, pkcs7.OIDDigestAlgorithmSHA256},
		{"SHA-1", []scep.ResponseOption{scep.WithResponseDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1)}, pkcs7.OIDDigestAlgorithmSHA1},
		{"default again", nil, pkcs7.OIDDigestAlgorithmSHA1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []struct {
				name         string
				makeResponse func() (*scep.PKIMessage, error)
			}{
				{"Success", func() (*scep.PKIMessage, error) { return request.Success(caCert, caKey, caCert, tc.options...) }},
				{"SuccessWithRequestEncryption", func() (*scep.PKIMessage, error) {
					return request.SuccessWithRequestEncryption(caCert, caKey, caCert, tc.options...)
				}},
			} {
				t.Run(method.name, func(t *testing.T) {
					response, err := method.makeResponse()
					if err != nil {
						t.Fatal(err)
					}
					p7, err := pkcs7.Parse(response.Raw)
					if err != nil {
						t.Fatal(err)
					}
					if len(p7.Signers) != 1 || !p7.Signers[0].DigestAlgorithm.Algorithm.Equal(tc.digest) {
						t.Fatalf("CertRep digest = %v, want %v", p7.Signers[0].DigestAlgorithm.Algorithm, tc.digest)
					}
				})
			}
		})
	}
}
