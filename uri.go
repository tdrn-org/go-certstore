// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certstore

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hdecarne-github/go-certstore/storage"
)

// NewStoreFromURI creates a certificate store based upon the submitted uri and base path.
//
// Supported uri formats are:
//
//  1. memory://<?parameters> (e.g. memory://?cache_ttl=60s&version_limit=10)
//  2. fs://<path><?parameters> (e.g. fs://./certs?cache_ttl=60s&version_limit=10)
//
// Relative paths are evaluated using the submitted base path.
//
// Known uri parameters are:
//
//  1. cache_ttl: The cache ttl (see [time.ParseDuration])
//  1. cache_ttl: The version limit (see [time.ParseUint])
//
// See [NewStore] for further details.
func NewStoreFromURI(uri string, basePath string) (*Registry, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI '%s' (cause: %w)", uri, err)
	}
	context := &decodeStoreURIContext{uri: parsedURI}
	err = context.decodeStoreURI()
	if err != nil {
		return nil, err
	}
	backend, err := context.backendFactory(context, basePath)
	if err != nil {
		return nil, err
	}
	registry, err := NewStore(backend, context.cacheTTL)
	if err != nil {
		return nil, err
	}
	return registry, nil
}

type decodeStoreURIContext struct {
	uri            *url.URL
	backendFactory func(context *decodeStoreURIContext, basePath string) (storage.Backend, error)
	cacheTTL       time.Duration
	versionLimit   storage.VersionLimit
}

func (context *decodeStoreURIContext) decodeStoreURI() error {
	err := context.decodeStoreURIScheme()
	if err != nil {
		return err
	}
	err = context.decodeStoreURIParameters()
	if err != nil {
		return err
	}
	return nil
}

func (context *decodeStoreURIContext) decodeStoreURIScheme() error {
	switch context.uri.Scheme {
	case "memory":
		context.backendFactory = newMemoryStorageFromURI
	case "fs":
		context.backendFactory = newFSStorageFromURI
	default:
		return fmt.Errorf("unrecognized backend scheme '%s'", context.uri.Scheme)
	}
	return nil
}

func newMemoryStorageFromURI(context *decodeStoreURIContext, basePath string) (storage.Backend, error) {
	return storage.NewMemoryStorage(context.versionLimit), nil
}

func newFSStorageFromURI(context *decodeStoreURIContext, basePath string) (storage.Backend, error) {
	path := filepath.Join(basePath, context.uri.Path)
	return storage.NewFSStorage(path, context.versionLimit)
}

func (context *decodeStoreURIContext) decodeStoreURIParameters() error {
	parameters, err := url.ParseQuery(context.uri.RawQuery)
	if err != nil {
		return fmt.Errorf("failed to parse URI parameters '%s' (cause: %w)", context.uri.RawQuery, err)
	}
	for key, values := range parameters {
		value, err := context.decodeStoreURIParameterValue(key, values)
		if err != nil {
			return err
		}
		switch key {
		case "cache_ttl":
			err = context.decodeStoreURICacheTTL(value)
		case "version_limit":
			err = context.decodeStoreURIVersionLimit(value)
		default:
			err = fmt.Errorf("unrecognized URI parameter '%s'", key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (context *decodeStoreURIContext) decodeStoreURIParameterValue(key string, values []string) (string, error) {
	valueCount := len(values)
	if valueCount > 1 {
		return "", fmt.Errorf("multiple values set for parameter '%s'", key)
	}
	return values[0], nil
}

func (context *decodeStoreURIContext) decodeStoreURIVersionLimit(value string) error {
	parsedValue, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse version limit '%s' (cause: %w)", value, err)
	}
	context.versionLimit = storage.VersionLimit(parsedValue)
	return nil
}

func (context *decodeStoreURIContext) decodeStoreURICacheTTL(value string) error {
	parsedCacheTTL, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("failed to parse cache TTL '%s' (cause: %w)", value, err)
	}
	context.cacheTTL = parsedCacheTTL
	return nil
}
