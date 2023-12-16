// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

const fsBackendURIPattern = "fs://%s"

const fsBackendDirPerm = 0700
const fsBackendFilePerm = 0600

type fsBackend struct {
	versionLimit VersionLimit
	uri          string
	path         string
	logger       *zerolog.Logger
}

func (backend *fsBackend) URI() string {
	return backend.uri
}

func (backend *fsBackend) Create(name string, data []byte) (string, error) {
	backend.logger.Debug().Msgf("creating entry '%s'...", name)
	nextName := name
	nextSuffix := 1
	for {
		entryPath, err := backend.checkEntryPath(nextName, true)
		if err != nil {
			return "", err
		}
		versions, err := backend.readEntryVersions(entryPath, true)
		if err != nil {
			return "", err
		}
		if len(versions) != 0 {
			nextSuffix++
			nextName = fmt.Sprintf("%s (%d)", name, nextSuffix)
			continue
		}
		versionFile := backend.resolveEntryVersionFile(entryPath, 1)
		err = os.WriteFile(versionFile, data, fsBackendFilePerm)
		if err != nil {
			return nextName, fmt.Errorf("failed to write entry version '%s' (cause: %w)", versionFile, err)
		}
		backend.logger.Debug().Msgf("created entry '%s'", nextName)
		return nextName, nil
	}
}

func (backend *fsBackend) Update(name string, data []byte) (Version, error) {
	backend.logger.Debug().Msgf("updating entry '%s'...", name)
	entryPath, err := backend.checkEntryPath(name, false)
	if err != nil {
		return 0, err
	}
	versions, err := backend.readEntryVersions(entryPath, false)
	if err != nil {
		return 0, err
	}
	versionCount := len(versions)
	nextVersion := versions[0] + 1
	for {
		if VersionLimit(versionCount) < backend.versionLimit {
			break
		}
		removeFile := backend.resolveEntryVersionFile(entryPath, versions[versionCount-1])
		err = os.Remove(removeFile)
		if err != nil {
			return 0, fmt.Errorf("failed to remove entry version '%s' (cause: %w)", removeFile, err)
		}
		versionCount--
	}
	nextVersionFile := backend.resolveEntryVersionFile(entryPath, nextVersion)
	err = os.WriteFile(nextVersionFile, data, fsBackendFilePerm)
	if err != nil {
		return 0, fmt.Errorf("failed to write entry version '%s' (cause: %w)", nextVersionFile, err)
	}
	backend.logger.Debug().Msgf("updated entry '%s' to version %d", name, nextVersion)
	return nextVersion, nil
}

func (backend *fsBackend) List() (Names, error) {
	dirEntries, err := os.ReadDir(backend.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage path '%s' (cause: %w)", backend.path, err)
	}
	names := make([]string, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		names = append(names, dirEntry.Name())
	}
	return &fsBackendNames{names: names}, nil
}

type fsBackendNames struct {
	next  int
	names []string
}

func (names *fsBackendNames) Next() string {
	name := ""
	if names.next < len(names.names) {
		name = names.names[names.next]
		names.next++
	}
	return name
}

func (backend *fsBackend) Get(name string) ([]byte, error) {
	entryPath, err := backend.checkEntryPath(name, false)
	if err != nil {
		return nil, err
	}
	versions, err := backend.readEntryVersions(entryPath, false)
	if err != nil {
		return nil, err
	}
	versionFile := backend.resolveEntryVersionFile(entryPath, versions[0])
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read entry version '%s' (cause: %w)", versionFile, err)
	}
	return data, nil
}

func (backend *fsBackend) GetVersions(name string) ([]Version, error) {
	entryPath, err := backend.checkEntryPath(name, false)
	if err != nil {
		return nil, err
	}
	versions, err := backend.readEntryVersions(entryPath, false)
	if err != nil {
		return nil, err
	}
	return versions, nil
}

func (backend *fsBackend) GetVersion(name string, version Version) ([]byte, error) {
	entryPath, err := backend.checkEntryPath(name, false)
	if err != nil {
		return nil, err
	}
	versionFile := backend.resolveEntryVersionFile(entryPath, version)
	data, err := os.ReadFile(versionFile)
	if os.IsNotExist(err) {
		return nil, ErrNotExist
	} else if err != nil {
		return nil, fmt.Errorf("failed to read entry version '%s' (cause: %w)", versionFile, err)
	}
	return data, nil
}

func (backend *fsBackend) Log(name string, message string) error {
	entryPath, err := backend.checkEntryPath(name, true)
	if err != nil {
		return err
	}
	logPath := filepath.Join(entryPath, "log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fsBackendFilePerm)
	if err != nil {
		return fmt.Errorf("failed to open log file '%s' (cause: %w)", logPath, err)
	}
	defer logFile.Close()
	_, err = logFile.WriteString(message)
	if err != nil {
		return fmt.Errorf("failed to write log file '%s' (cause: %w)", logPath, err)
	}
	return nil
}

func (backend *fsBackend) checkEntryPath(name string, create bool) (string, error) {
	entryPath := filepath.Join(backend.path, name)
	pathInfo, err := os.Stat(entryPath)
	if os.IsNotExist(err) {
		if !create {
			return entryPath, ErrNotExist
		}
		backend.logger.Info().Msgf("creating entry path '%s'...", entryPath)
		err = os.MkdirAll(entryPath, fsBackendDirPerm)
		if err != nil {
			return entryPath, fmt.Errorf("failed to create entry path '%s' (cause: %w)", entryPath, err)
		}
	} else if !pathInfo.IsDir() {
		return entryPath, fmt.Errorf("entry path '%s' is not a directory", entryPath)
	}
	return entryPath, nil
}

func (backend *fsBackend) readEntryVersions(entryPath string, ignoreEmpty bool) ([]Version, error) {
	dirEntries, err := os.ReadDir(entryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read entry path '%s' (cause: %w)", entryPath, err)
	}
	if !ignoreEmpty && len(dirEntries) == 0 {
		return nil, fmt.Errorf("invalid entry path '%s'", entryPath)
	}
	versions := make([]Version, 0)
	for _, dirEntry := range dirEntries {
		parsedVersion, err := strconv.ParseUint(dirEntry.Name(), 10, 64)
		if err != nil {
			continue
		}
		versions = append(versions, Version(parsedVersion))
	}
	sort.Slice(versions, func(i int, j int) bool { return versions[i] > versions[j] })
	return versions, nil
}

func (backend *fsBackend) resolveEntryVersionFile(entryPath string, version Version) string {
	return filepath.Join(entryPath, strconv.FormatUint(uint64(version), 10))
}

func NewFSStorage(versionLimit VersionLimit, path string) (Backend, error) {
	uri := fmt.Sprintf(fsBackendURIPattern, path)
	logger := log.RootLogger().With().Str("Backend", uri).Logger()
	checkedPath, err := checkFSStoragePath(path, &logger)
	if err != nil {
		return nil, err
	}
	return &fsBackend{
		versionLimit: versionLimit,
		uri:          uri,
		path:         checkedPath,
		logger:       &logger,
	}, nil
}

func checkFSStoragePath(path string, logger *zerolog.Logger) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return absolutePath, fmt.Errorf("unable to determin absolute path for '%s' (cause: %w)", path, err)
	}
	pathInfo, err := os.Stat(absolutePath)
	if os.IsNotExist(err) {
		logger.Info().Msgf("creating storage path '%s'...", absolutePath)
		err = os.MkdirAll(absolutePath, fsBackendDirPerm)
		if err != nil {
			return absolutePath, fmt.Errorf("failed to create storage path '%s' (cause: %w)", absolutePath, err)
		}
	} else if !pathInfo.IsDir() {
		return absolutePath, fmt.Errorf("storage path '%s' is not a directory", absolutePath)
	}
	return absolutePath, nil
}
