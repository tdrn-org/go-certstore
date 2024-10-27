// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package storage

import (
	"container/heap"
	"fmt"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-log"
)

type entryVersion struct {
	version   Version
	data      []byte
	heapIndex int
}

type entryVersions []*entryVersion

func (versions entryVersions) Len() int {
	return len(versions)
}

func (versions entryVersions) Less(i int, j int) bool {
	return versions[i].version < versions[j].version
}

func (versions entryVersions) Swap(i int, j int) {
	versions[i], versions[j] = versions[j], versions[i]
	versions[i].heapIndex = i
	versions[j].heapIndex = j
}

func (versions *entryVersions) Push(x any) {
	n := len(*versions)
	version := x.(*entryVersion)
	version.heapIndex = n
	*versions = append(*versions, version)
}

func (versions *entryVersions) Pop() any {
	old := *versions
	n := len(old)
	version := old[n-1]
	old[n-1] = nil
	version.heapIndex = -1
	*versions = old[0 : n-1]
	return version
}

const memoryBackendURI = "memory://"

type memoryBackend struct {
	versionLimit VersionLimit
	lock         sync.RWMutex
	entries      map[string]entryVersions
	logger       *zerolog.Logger
}

func (backend *memoryBackend) URI() string {
	return memoryBackendURI
}

func (backend *memoryBackend) Create(name string, data []byte) (string, error) {
	backend.lock.Lock()
	defer backend.lock.Unlock()
	backend.logger.Debug().Msgf("creating entry '%s*'...", name)
	nextName := name
	nextSuffix := 1
	for {
		versions, exists := backend.entries[nextName]
		if exists {
			nextSuffix++
			nextName = fmt.Sprintf("%s (%d)", name, nextSuffix)
			continue
		}
		entry := &entryVersion{
			version:   1,
			data:      data,
			heapIndex: 0,
		}
		versions = entryVersions{entry}
		heap.Init(&versions)
		backend.entries[nextName] = versions
		backend.logger.Debug().Msgf("created entry '%s'", nextName)
		return nextName, nil
	}
}

func (backend *memoryBackend) Update(name string, data []byte) (Version, error) {
	backend.lock.Lock()
	defer backend.lock.Unlock()
	backend.logger.Debug().Msgf("updating entry '%s'...", name)
	versions, update := backend.entries[name]
	if !update {
		return 0, ErrNotExist
	}
	versionCount := len(versions)
	nextVersion := versions[versionCount-1].version + 1
	if VersionLimit(versionCount)+1 > backend.versionLimit {
		heap.Pop(&versions)
	}
	entry := &entryVersion{
		version: nextVersion,
		data:    data,
	}
	heap.Push(&versions, entry)
	backend.entries[name] = versions
	backend.logger.Debug().Msgf("updated entry '%s' to version %d", name, entry.version)
	return entry.version, nil
}

func (backend *memoryBackend) Delete(name string) error {
	backend.lock.Lock()
	defer backend.lock.Unlock()
	backend.logger.Debug().Msgf("deleting entry '%s'...", name)
	_, exists := backend.entries[name]
	if !exists {
		return ErrNotExist
	}
	delete(backend.entries, name)
	backend.logger.Debug().Msgf("entry '%s' deleted", name)
	return nil
}

func (backend *memoryBackend) List() (Names, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()
	names := make([]string, 0, len(backend.entries))
	for name := range backend.entries {
		names = append(names, name)
	}
	slices.Sort(names)
	return &memoryBackendNames{names: names}, nil
}

type memoryBackendNames struct {
	next  int
	names []string
}

func (names *memoryBackendNames) Next() string {
	name := ""
	if names.next < len(names.names) {
		name = names.names[names.next]
		names.next++
	}
	return name
}

func (backend *memoryBackend) Get(name string) ([]byte, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()
	versions, exists := backend.entries[name]
	if !exists {
		return nil, ErrNotExist
	}
	return versions[len(versions)-1].data, nil
}

func (backend *memoryBackend) GetVersions(name string) ([]Version, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()
	versions, exists := backend.entries[name]
	if !exists {
		return nil, ErrNotExist
	}
	entryCount := len(versions)
	entryVersions := make([]Version, entryCount)
	for entryIndex, entry := range versions {
		entryVersions[entryCount-entryIndex-1] = entry.version
	}
	return entryVersions, nil
}

func (backend *memoryBackend) GetVersion(name string, version Version) ([]byte, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()
	versions, exists := backend.entries[name]
	if !exists {
		return nil, ErrNotExist
	}
	for _, entry := range versions {
		if entry.version == version {
			return entry.data, nil
		}
	}
	return nil, ErrNotExist
}

func (backend *memoryBackend) Log(name string, message string) error {
	backend.logger.Info().Msgf("log: %s", message)
	return nil
}

func NewMemoryStorage(versionLimit VersionLimit) Backend {
	logger := log.RootLogger().With().Str("Backend", memoryBackendURI).Logger()
	return &memoryBackend{
		versionLimit: versionLimit.normalize(),
		entries:      make(map[string]entryVersions),
		logger:       &logger,
	}
}
