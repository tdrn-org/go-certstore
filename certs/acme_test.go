// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/certs/acme"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/stretchr/testify/require"
)

func TestACMECertificateFactory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "TestACMECertificateFactory*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	config := loadAndPrepareACMEConfig(t, "./acme/testdata/acme-test.yaml", tempDir)
	cf := certs.NewACMECertificateFactory([]string{"localhost"}, config, "Test", keys.ProviderKeyPairFactories("RSA")[0])
	require.NotNil(t, cf)
	require.Equal(t, "ACME[Test]", cf.Name())
	privateKey, cert, err := cf.New()
	require.NotNil(t, privateKey)
	require.NotNil(t, cert)
	require.NoError(t, err)
}

func loadAndPrepareACMEConfig(t *testing.T, configPath string, tempDir string) *acme.Config {
	config, err := acme.LoadConfig("./acme/testdata/acme-test.yaml")
	require.NoError(t, err)
	require.NotNil(t, config)
	certificateFiles := make([]string, 0)
	for i, provider := range config.Providers {
		if !filepath.IsAbs(provider.RegistrationPath) {
			updatedProvider := provider
			updatedProvider.RegistrationPath = filepath.Join(tempDir, provider.RegistrationPath)
			config.Providers[i] = updatedProvider
		}
		providerUrl, err := url.Parse(provider.URL)
		require.NoError(t, err)
		certificates, err := certs.ServerCertificates("tcp", providerUrl.Host)
		require.NoError(t, err)
		certificateFile := filepath.Join(tempDir, provider.Name+".pem")
		err = certs.WriteCertificates(certificateFile, certificates, 0600)
		require.NoError(t, err)
		certificateFiles = append(certificateFiles, certificateFile)
	}
	os.Setenv("LEGO_CA_CERTIFICATES", strings.Join(certificateFiles, string(os.PathListSeparator)))
	return config
}
