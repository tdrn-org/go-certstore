// Copyright (C) 2023-2025 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package acme_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-certstore/certs/acme"
)

func TestLoadConfig(t *testing.T) {
	config, err := acme.LoadConfig("./testdata/acme-test.yaml")
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Equal(t, 2, len(config.Providers))
	provider1 := config.Providers["Test1"]
	require.NotNil(t, provider1)
	require.Equal(t, "Test1", provider1.Name)
	require.True(t, provider1.Enabled)
	provider2 := config.Providers["Test2"]
	require.NotNil(t, provider2)
	require.Equal(t, "Test2", provider2.Name)
	require.False(t, provider2.Enabled)
}
