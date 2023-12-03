// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package storage_test

import (
	"os"
	"slices"
	"testing"

	"github.com/hdecarne-github/go-certstore/storage"
	"github.com/stretchr/testify/require"
)

const testVersionLimit storage.VersionLimit = 2

func TestMemoryStorageNew(t *testing.T) {
	checkNew(t, storage.NewMemoryStorage(testVersionLimit))
}
func TestMemoryStoragePut(t *testing.T) {
	checkPut(t, storage.NewMemoryStorage(testVersionLimit))
}

func TestMemoryStorageGetX(t *testing.T) {
	checkGetX(t, storage.NewMemoryStorage(testVersionLimit))
}

func TestMemoryStorageVersions(t *testing.T) {
	checkVersions(t, storage.NewMemoryStorage(testVersionLimit))
}

func TestFSStorageNew(t *testing.T) {
	path, err := os.MkdirTemp("", "TestFSStorageNew*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	checkNew(t, backend)
}
func TestFSStoragePut(t *testing.T) {
	path, err := os.MkdirTemp("", "TestFSStoragePut*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	checkPut(t, backend)
}
func TestFSStorageGetX(t *testing.T) {
	path, err := os.MkdirTemp("", "TestFSStoragePut*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	checkGetX(t, backend)
}

func TestFSStorageGetVersions(t *testing.T) {
	path, err := os.MkdirTemp("", "TestFSStoragePut*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	checkVersions(t, backend)
}

func checkNew(t *testing.T, backend storage.Backend) {
	require.NotNil(t, backend)
}

func checkPut(t *testing.T, backend storage.Backend) {
	// checkPut1
	name1 := "checkPut1"
	data1 := []byte{byte(1)}
	version1, err := backend.Put(name1, data1)
	require.NoError(t, err)
	require.Equal(t, storage.Version(1), version1)
	data, err := backend.Get(name1)
	require.NoError(t, err)
	require.Equal(t, data1, data)
	// checkPut2
	name2 := "checkPut2"
	data2 := []byte{byte(2)}
	version2, err := backend.Put(name2, data2)
	require.NoError(t, err)
	require.Equal(t, storage.Version(1), version2)
	data, err = backend.Get(name2)
	require.NoError(t, err)
	require.Equal(t, data2, data)
	// list
	checkList(t, backend, []string{name1, name2})
}

func checkList(t *testing.T, backend storage.Backend, expected []string) {
	names, err := backend.List()
	require.NoError(t, err)
	actual := make([]string, 0)
	for {
		name := names.Next()
		if name == "" {
			break
		}
		actual = append(actual, name)
	}
	require.Equal(t, len(expected), len(actual))
	for _, expectedName := range expected {
		require.True(t, slices.Contains(actual, expectedName))
	}
}

func checkGetX(t *testing.T, backend storage.Backend) {
	name := "checkGet"
	data, err := backend.Get(name)
	require.Equal(t, storage.ErrNotExist, err)
	require.Nil(t, data)
	versions, err := backend.GetVersions(name)
	require.Equal(t, storage.ErrNotExist, err)
	require.Nil(t, versions)
	version, err := backend.GetVersion(name, 1)
	require.Equal(t, storage.ErrNotExist, err)
	require.Nil(t, version)
}

func checkVersions(t *testing.T, backend storage.Backend) {
	// version limit
	name := "checkVersionLimit"
	data1 := []byte{byte(1)}
	version1, err := backend.Put(name, data1)
	require.NoError(t, err)
	require.Equal(t, storage.Version(1), version1)
	data2 := []byte{byte(2)}
	version2, err := backend.Put(name, data2)
	require.NoError(t, err)
	require.Equal(t, storage.Version(2), version2)
	data3 := []byte{byte(3)}
	version3, err := backend.Put(name, data3)
	require.NoError(t, err)
	require.Equal(t, storage.Version(3), version3)
	versions, err := backend.GetVersions(name)
	require.NoError(t, err)
	require.Equal(t, []storage.Version{3, 2}, versions)
}
