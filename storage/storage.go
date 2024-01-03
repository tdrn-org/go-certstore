// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package storage provides different backends for versioned data storage.
package storage

import "errors"

type VersionLimit uint64

const MaxVersionLimit VersionLimit = 255

func (limit VersionLimit) normalize() VersionLimit {
	if limit <= 0 || MaxVersionLimit < limit {
		return MaxVersionLimit
	}
	return limit
}

type Version uint64

type Names interface {
	Next() string
}

type Backend interface {
	URI() string
	Create(name string, data []byte) (string, error)
	Update(name string, data []byte) (Version, error)
	Delete(name string) error
	List() (Names, error)
	Get(name string) ([]byte, error)
	GetVersions(name string) ([]Version, error)
	GetVersion(name string, version Version) ([]byte, error)
	Log(name string, message string) error
}

var ErrNotExist = errors.New("storage item does not exist")
