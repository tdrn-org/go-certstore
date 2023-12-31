// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package certs provides functions for X.509 certificate management.
package certs

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
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

// RevocationListFactory interface provides a unified way to create X.509 revocation lists.
type RevocationListFactory interface {
	// Name returns the name of this factory.
	Name() string
	// New creates a new X.509 revocation list.
	New(issuer *x509.Certificate, signer crypto.PrivateKey) (*x509.RevocationList, error)
}

// IsRoot checks whether the given certificate is a root certificate.
func IsRoot(cert *x509.Certificate) bool {
	return IsIssuedBy(cert, cert)
}

// IsIssuedBy checks whether the given certificate has been issued/signed by the given issuer certificate.
func IsIssuedBy(cert *x509.Certificate, issuer *x509.Certificate) bool {
	return cert.CheckSignatureFrom(issuer) == nil
}

// ParseDN parses a X.509 certificate's Distinguished Name (DN) attribute.
func ParseDN(dn string) (*pkix.Name, error) {
	ldapDN, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, fmt.Errorf("invalid DN '%s' (cause: %w)", dn, err)
	}
	rdns := make([]pkix.RelativeDistinguishedNameSET, 0)
	for _, ldapRDN := range ldapDN.RDNs {
		rdn := make([]pkix.AttributeTypeAndValue, 0)
		for _, ldapRDNAttribute := range ldapRDN.Attributes {
			rdnType, err := parseLdapRDNType(ldapRDNAttribute.Type)
			if err != nil {
				return nil, err
			}
			rdn = append(rdn, pkix.AttributeTypeAndValue{Type: rdnType, Value: ldapRDNAttribute.Value})
		}
		rdns = append(rdns, rdn)
	}
	parsedDN := &pkix.Name{}
	parsedDN.FillFromRDNSequence((*pkix.RDNSequence)(&rdns))
	return parsedDN, nil
}

func parseLdapRDNType(ldapRDNType string) (asn1.ObjectIdentifier, error) {
	switch ldapRDNType {
	case "CN":
		return []int{2, 5, 4, 3}, nil
	case "SERIALNUMBER":
		return []int{2, 5, 4, 5}, nil
	case "C":
		return []int{2, 5, 4, 6}, nil
	case "L":
		return []int{2, 5, 4, 7}, nil
	case "ST":
		return []int{2, 5, 4, 8}, nil
	case "STREET":
		return []int{2, 5, 4, 9}, nil
	case "O":
		return []int{2, 5, 4, 10}, nil
	case "OU":
		return []int{2, 5, 4, 11}, nil
	case "POSTALCODE":
		return []int{2, 5, 4, 17}, nil
	case "UID":
		return []int{0, 9, 2342, 19200300, 100, 1, 1}, nil
	case "DC":
		return []int{0, 9, 2342, 19200300, 100, 1, 25}, nil
	}
	return nil, fmt.Errorf("unrecognized RDN type '%s'", ldapRDNType)
}

var serialNumberLock sync.Mutex = sync.Mutex{}

func nextSerialNumber() *big.Int {
	// lock to avoid double numbers via multiple goroutines
	serialNumberLock.Lock()
	defer serialNumberLock.Unlock()
	// wait at least one update, to ensure this functions never returns the same result twice
	current := time.Now().UnixMilli()
	for {
		next := time.Now().UnixMilli()
		if next != current {
			return big.NewInt(next)
		}
	}
}
