// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package acme_test

import (
	"testing"

	"github.com/hdecarne-github/go-certstore/certs/acme"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	config, err := acme.LoadConfig("./testdata/acme-test.yaml")
	require.NoError(t, err)
	require.NotNil(t, config)
}
