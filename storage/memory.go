// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package storage

import (
	"container/heap"
	"sync"
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

type memoryBackend struct {
	versionLimit VersionLimit
	lock         sync.RWMutex
	entries      map[string]entryVersions
}

func (backend *memoryBackend) Put(name string, data []byte) (Version, error) {
	backend.lock.Lock()
	defer backend.lock.Unlock()
	versions, update := backend.entries[name]
	var entry *entryVersion
	if update {
		versionCount := len(versions)
		nextVersion := versions[versionCount-1].version + 1
		if VersionLimit(versionCount)+1 > backend.versionLimit {
			heap.Pop(&versions)
		}
		entry = &entryVersion{
			version: nextVersion,
			data:    data,
		}
		heap.Push(&versions, entry)
	} else {
		entry = &entryVersion{
			version:   1,
			data:      data,
			heapIndex: 0,
		}
		versions = entryVersions{entry}
		heap.Init(&versions)
	}
	backend.entries[name] = versions
	return entry.version, nil
}

func (backend *memoryBackend) List() (Names, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()
	names := make([]string, 0, len(backend.entries))
	for name := range backend.entries {
		names = append(names, name)
	}
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

func NewMemoryStorage(versionLimit VersionLimit) Backend {
	return &memoryBackend{
		versionLimit: versionLimit,
		entries:      make(map[string]entryVersions),
	}
}
