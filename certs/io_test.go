// Copyright (C) 2023-2025 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-certstore/certs"
)

const pemCertificatesFile = "./testdata/fullchain.pem"
const derCertificatesFile = "./testdata/fullchain.der"
const pemKeyFile = "./testdata/key.pem"
const derKeyFile = "./testdata/key.der"

func TestReadPEMCertificates(t *testing.T) {
	reader, err := os.Open(pemCertificatesFile)
	require.NoError(t, err)
	defer reader.Close()
	certificates, err := certs.ReadCertificates(reader)
	require.NoError(t, err)
	require.NotNil(t, certificates)
	require.Equal(t, 2, len(certificates))
}

func TestReadPEMCertificatesFile(t *testing.T) {
	certificates, err := certs.ReadCertificatesFile(pemCertificatesFile)
	require.NoError(t, err)
	require.NotNil(t, certificates)
	require.Equal(t, 2, len(certificates))
}

func TestReadDERCertificates(t *testing.T) {
	reader, err := os.Open(derCertificatesFile)
	require.NoError(t, err)
	defer reader.Close()
	certificates, err := certs.ReadCertificates(reader)
	require.NoError(t, err)
	require.NotNil(t, certificates)
	require.Equal(t, 2, len(certificates))
}

func TestReadDERCertificatesFile(t *testing.T) {
	certificates, err := certs.ReadCertificatesFile(derCertificatesFile)
	require.NoError(t, err)
	require.NotNil(t, certificates)
	require.Equal(t, 2, len(certificates))
}

func TestReadPEMKey(t *testing.T) {
	reader, err := os.Open(pemKeyFile)
	require.NoError(t, err)
	defer reader.Close()
	key, err := certs.ReadKey(reader)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestReadPEMKeyFile(t *testing.T) {
	key, err := certs.ReadKeyFile(pemKeyFile)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestReadDERKey(t *testing.T) {
	reader, err := os.Open(derKeyFile)
	require.NoError(t, err)
	defer reader.Close()
	key, err := certs.ReadKey(reader)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestReadDERKeyFile(t *testing.T) {
	key, err := certs.ReadKeyFile(derKeyFile)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestWritePEMCertificates(t *testing.T) {
	certificates, err := certs.ReadCertificatesFile(pemCertificatesFile)
	require.NoError(t, err)
	var buffer bytes.Buffer
	err = certs.WriteCertificatesPEM(&buffer, certificates)
	require.NoError(t, err)
	certificates2, err := certs.ReadCertificates(&buffer)
	require.NoError(t, err)
	require.Equal(t, certificates, certificates2)
}

func TestWritePEMCertificatesFile(t *testing.T) {
	certificates, err := certs.ReadCertificatesFile(pemCertificatesFile)
	require.NoError(t, err)
	file, err := os.CreateTemp("", "PEMCertificate*")
	require.NoError(t, err)
	defer func() {
		os.Remove(file.Name())
	}()
	file.Close()
	err = certs.WriteCertificatesPEMFile(file.Name(), certificates, 0600)
	require.NoError(t, err)
	certificates2, err := certs.ReadCertificatesFile(file.Name())
	require.NoError(t, err)
	require.Equal(t, certificates, certificates2)
}

func TestWritePEMKey(t *testing.T) {
	key, err := certs.ReadKeyFile(pemKeyFile)
	require.NoError(t, err)
	var buffer bytes.Buffer
	err = certs.WriteKeyPEM(&buffer, key)
	require.NoError(t, err)
	key2, err := certs.ReadKey(&buffer)
	require.NoError(t, err)
	require.Equal(t, key, key2)
}

func TestWritePEMKeyFile(t *testing.T) {
	key, err := certs.ReadKeyFile(pemKeyFile)
	require.NoError(t, err)
	file, err := os.CreateTemp("", "PEMKey*")
	require.NoError(t, err)
	defer func() {
		os.Remove(file.Name())
	}()
	file.Close()
	err = certs.WriteKeyPEMFile(file.Name(), key, 0600)
	require.NoError(t, err)
	key2, err := certs.ReadKeyFile(file.Name())
	require.NoError(t, err)
	require.Equal(t, key, key2)
}

func TestWriteDERCertificates(t *testing.T) {
	certificates, err := certs.ReadCertificatesFile(derCertificatesFile)
	require.NoError(t, err)
	var buffer bytes.Buffer
	err = certs.WriteCertificatesDER(&buffer, certificates)
	require.NoError(t, err)
	certificates2, err := certs.ReadCertificates(&buffer)
	require.NoError(t, err)
	require.Equal(t, certificates, certificates2)
}

func TestWriteDERCertificatesFile(t *testing.T) {
	certificates, err := certs.ReadCertificatesFile(derCertificatesFile)
	require.NoError(t, err)
	file, err := os.CreateTemp("", "DERCertificate*")
	require.NoError(t, err)
	defer func() {
		os.Remove(file.Name())
	}()
	file.Close()
	err = certs.WriteCertificatesDERFile(file.Name(), certificates, 0600)
	require.NoError(t, err)
	certificates2, err := certs.ReadCertificatesFile(file.Name())
	require.NoError(t, err)
	require.Equal(t, certificates, certificates2)
}

func TestWriteDERKey(t *testing.T) {
	key, err := certs.ReadKeyFile(derKeyFile)
	require.NoError(t, err)
	var buffer bytes.Buffer
	err = certs.WriteKeyDER(&buffer, key)
	require.NoError(t, err)
	key2, err := certs.ReadKey(&buffer)
	require.NoError(t, err)
	require.Equal(t, key, key2)
}

func TestWriteDERKeyFile(t *testing.T) {
	key, err := certs.ReadKeyFile(derKeyFile)
	require.NoError(t, err)
	file, err := os.CreateTemp("", "DERKey*")
	require.NoError(t, err)
	defer func() {
		os.Remove(file.Name())
	}()
	file.Close()
	err = certs.WriteKeyDERFile(file.Name(), key, 0600)
	require.NoError(t, err)
	key2, err := certs.ReadKeyFile(file.Name())
	require.NoError(t, err)
	require.Equal(t, key, key2)
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
