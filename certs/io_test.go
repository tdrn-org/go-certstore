// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/stretchr/testify/require"
)

func TestReadPEMCertificates(t *testing.T) {
	certs, err := certs.ReadCertificates("./testdata/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestReadDERCertificates(t *testing.T) {
	certs, err := certs.ReadCertificates("./testdata/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestFetchPEMCertificates(t *testing.T) {
	certs, err := certs.FetchCertificates("https://letsencrypt.org/certs/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestFetchDERCertificates(t *testing.T) {
	certs, err := certs.FetchCertificates("https://letsencrypt.org/certs/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestServerCertificates(t *testing.T) {
	certs, err := certs.ServerCertificates("tcp", "valid-isrgrootx1.letsencrypt.org:443")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 2, len(certs))
}

func TestParseDN(t *testing.T) {
	dn := &pkix.Name{
		CommonName:         "CommonName",
		Locality:           []string{"Locality"},
		Country:            []string{"Country"},
		Organization:       []string{"Organization"},
		OrganizationalUnit: []string{"OrganizationUnit"},
		PostalCode:         []string{"PostalCode"},
		Province:           []string{"Province"},
		SerialNumber:       "SerialNumber",
		StreetAddress:      []string{"StreetAddress"},
	}
	parsed, err := certs.ParseDN(dn.String())
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, dn.String(), parsed.String())
}
