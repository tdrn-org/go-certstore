// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"os"
	"testing"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/stretchr/testify/require"
)

func TestReadPEMCertificates(t *testing.T) {
	certificates, err := certs.ReadCertificates("./testdata/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certificates)
	require.Equal(t, 1, len(certificates))
}

func TestReadDERCertificates(t *testing.T) {
	certificates, err := certs.ReadCertificates("./testdata/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certificates)
	require.Equal(t, 1, len(certificates))
}

func TestWritePEMCertificate(t *testing.T) {
	certificates, err := certs.ReadCertificates("./testdata/isrgrootx1.pem")
	require.NoError(t, err)
	file, err := os.CreateTemp("", "PEMCertificate*")
	require.NoError(t, err)
	defer func() {
		os.Remove(file.Name())
	}()
	file.Close()
	err = certs.WriteCertificatesPEM(file.Name(), certificates, 0600)
	require.NoError(t, err)
	certificates2, err := certs.ReadCertificates(file.Name())
	require.NoError(t, err)
	require.Equal(t, certificates, certificates2)
}

func TestWriteDERCertificate(t *testing.T) {
	certificates, err := certs.ReadCertificates("./testdata/isrgrootx1.der")
	require.NoError(t, err)
	file, err := os.CreateTemp("", "DERCertificate*")
	require.NoError(t, err)
	defer func() {
		os.Remove(file.Name())
	}()
	file.Close()
	err = certs.WriteCertificatesDER(file.Name(), certificates, 0600)
	require.NoError(t, err)
	certificates2, err := certs.ReadCertificates(file.Name())
	require.NoError(t, err)
	require.Equal(t, certificates, certificates2)
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
