// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package storage provides different backends for versioned data storage.
package storage

import "errors"

type VersionLimit uint64
type Version uint64

type Names interface {
	Next() string
}

type Backend interface {
	Put(name string, data []byte) (Version, error)
	List() (Names, error)
	Get(name string) ([]byte, error)
	GetVersions(name string) ([]Version, error)
	GetVersion(name string, version Version) ([]byte, error)
}

var ErrNotExist = errors.New("storage item does not exist")
