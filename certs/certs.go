// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package certs provides functions for X.509 certificate management.
package certs

import (
	"crypto"
	"crypto/x509"
)

// CertificateFactory interface provides a unified way to create X.509 certificates.
type CertificateFactory interface {
	// Name returns the name of this factory.
	Name() string
	// New creates a new X.509 certificate.
	New() (crypto.PrivateKey, *x509.Certificate, error)
}

// CertificateRequestFactory interface provides a unified way to create X.509 certificate requests.
type CertificateRequestFactory interface {
	// Name returns the name of this factory.
	Name() string
	// New creates a new X.509 certificate request.
	New() (crypto.PrivateKey, *x509.CertificateRequest, error)
}
