// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

const fsBackendDirPerm = 0700
const fsBackendFilePerm = 0600

type fsBackend struct {
	versionLimit VersionLimit
	path         string
}

func (backend *fsBackend) Put(name string, data []byte) (Version, error) {

	return 0, nil
}

func (backend *fsBackend) List() (Names, error) {
	return nil, nil
}

func (backend *fsBackend) Get(name string) ([]byte, error) {
	return nil, nil
}

func (backend *fsBackend) GetVersions(name string) ([]Version, error) {
	return nil, nil
}

func (backend *fsBackend) GetVersion(name string, version Version) ([]byte, error) {
	return nil, nil
}

func NewFSStorage(versionLimit VersionLimit, path string) (Backend, error) {
	checkedPath, err := checkFSStoragePath(path)
	if err != nil {
		return nil, err
	}
	return &fsBackend{
		versionLimit: versionLimit,
		path:         checkedPath,
	}, nil
}

func checkFSStoragePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return absolutePath, fmt.Errorf("unable to determin absolute path for '%s' (cause: %v)", path, err)
	}
	pathInfo, err := os.Stat(absolutePath)
	if os.IsNotExist(err) {
		err = os.MkdirAll(absolutePath, fsBackendDirPerm)
		if err != nil {
			return absolutePath, fmt.Errorf("failed to create storage path '%s' (cause: %v)", path, err)
		}
	} else if !pathInfo.IsDir() {
		return absolutePath, fmt.Errorf("storage path '%s' is not a directory", path)
	}
	return absolutePath, nil
}
