// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package scep

import (
	"encoding/asn1"

	"github.com/smallstep/pkcs7"
)

// ResponseOption configures a CertRep response without changing process-wide defaults.
// Without an option, responses use the PKCS#7 library's default digest.
type ResponseOption func(*responseOptions)

type responseOptions struct {
	digestAlgorithm asn1.ObjectIdentifier
}

// WithResponseDigestAlgorithm selects the digest used to sign one CertRep response.
func WithResponseDigestAlgorithm(algorithm asn1.ObjectIdentifier) ResponseOption {
	return func(options *responseOptions) {
		options.digestAlgorithm = append(asn1.ObjectIdentifier(nil), algorithm...)
	}
}

func responseDigestAlgorithm(options []ResponseOption) asn1.ObjectIdentifier {
	config := responseOptions{}
	for _, option := range options {
		option(&config)
	}
	return config.digestAlgorithm
}

func newResponseSignedData(content []byte, options []ResponseOption) (*pkcs7.SignedData, error) {
	signedData, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	if digest := responseDigestAlgorithm(options); len(digest) != 0 {
		signedData.SetDigestAlgorithm(digest)
	}
	return signedData, nil
}
