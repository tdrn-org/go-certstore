// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certstore_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hdecarne-github/go-certstore"
	"github.com/stretchr/testify/require"
)

func TestMemoryStoreURI(t *testing.T) {
	name := "Registry[memory://]"
	checkURI(t, "memory://", "", name)
	checkURI(t, "memory://?cache_ttl=60s&version_limit=10", "", name)
}

func TestFSStoreURI(t *testing.T) {
	basePath, err := os.MkdirTemp("", "TestFSStoreURI*")
	require.NoError(t, err)
	defer os.RemoveAll(basePath)
	name := fmt.Sprintf("Registry[fs://%s]", basePath)
	checkURI(t, "fs://.", basePath, name)
	checkURI(t, "fs://.?cache_ttl=60s&version_limit=10", basePath, name)
}

func TestInvalidStoreURI(t *testing.T) {
	_, err := certstore.NewStoreFromURI("foo://", "")
	require.Error(t, err)
	_, err = certstore.NewStoreFromURI("memory://?foo", "")
	require.Error(t, err)
	_, err = certstore.NewStoreFromURI("memory://?cache_ttl=0&cache_ttl=1", "")
	require.Error(t, err)
}

func checkURI(t *testing.T, uri string, basePath string, name string) {
	registry, err := certstore.NewStoreFromURI(uri, basePath)
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.Equal(t, name, registry.Name())
}
