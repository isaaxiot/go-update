package update

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var defaultHTTPRequester = HTTPRequester{}

// Updater is the configuration and runtime data for doing an update.
//
// Example:
//
//  updater := &selfupdate.Updater{
//  	CurrentVersion: version,
//  	ApiURL:         "http://updates.yourdomain.com/",
//  	BinURL:         "http://updates.yourdomain.com/",
//  	Dir:            "update/",
//  }
//  if updater != nil {
//  	go updater.Run()
//  }
type Updater struct {
	updater        *Update
	CurrentVersion string    // Currently running version.
	ApiURL         string    // Base URL for API requests (json files).
	BinURL         string    // Base URL for full binary downloads.
	Dir            string    // Directory to store selfupdate state.
	ForceCheck     bool      // Check for update regardless of cktime timestamp
	Requester      Requester //Optional parameter to override existing http request handler
	Info           Version
}

type Version struct {
	Version string `json:"version"`
	Hash    string `json:"hash"`
}

func (u *Updater) getExecRelativeDir(dir string) string {
	filename, _ := os.Executable()
	path := filepath.Join(filepath.Dir(filename), dir)
	return path
}

// Run starts the update check and apply cycle and returns true if an update was attempted or false if it was not.
// It returns the new version number if an update was applied or an empty string.
func (u *Updater) Run() (bool, string, error) {
	if err := os.MkdirAll(u.getExecRelativeDir(u.Dir), 0777); err != nil {
		return false, "", err
	}

	u.updater = &Update{
		// OldSavePath: u.getExecRelativeDir(u.Dir) + "/",
	}

	if err := u.updater.CheckPermissions(); err != nil {
		return false, "", err
	}
	tried, err := u.update()
	if err != nil {
		return tried, "", err
	}
	return tried, u.Info.Version, nil
}

// update returns true if an update was attempted
func (u *Updater) update() (bool, error) {
	path, err := os.Executable()
	if err != nil {
		return false, err
	}

	old, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer old.Close()

	if u.Info.Version == "" {
		err = u.fetchInfo()
		if err != nil {
			return false, err
		}
	}

	if u.Info.Version == u.CurrentVersion {
		return false, nil
	}
	checksum, err := hex.DecodeString(u.Info.Hash)
	if err != nil {
		return false, err
	}
	u.updater.Checksum = checksum

	bin, err := u.fetchBin()
	if err != nil {
		return false, err
	}

	// close the old binary before installing because on windows
	// it can't be renamed if a handle to the file is still open
	old.Close()

	if err := u.updater.Apply(bytes.NewBuffer(bin)); err != nil {
		if errr := RollbackError(err); errr != nil {
			// update and rollback failed
			return true, errr
		}
		return true, err
	}

	return true, nil
}

func (u *Updater) fetchInfo() error {
	r, err := u.fetch(u.ApiURL + url.QueryEscape(u.getPlat()) + ".json")
	if err != nil {
		return err
	}
	defer r.Close()

	err = json.NewDecoder(r).Decode(&u.Info)
	if err != nil {
		return err
	}
	return nil
}

func (u *Updater) fetchBin() ([]byte, error) {
	fmt.Println(u.BinURL + url.QueryEscape(u.getPlat()) + "/" + url.QueryEscape(u.Info.Version) + ".gz")
	r, err := u.fetch(u.BinURL + url.QueryEscape(u.getPlat()) + "/" + url.QueryEscape(u.Info.Version) + ".gz")
	if err != nil {
		return nil, err
	}
	defer r.Close()

	buf := new(bytes.Buffer)

	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}

	if _, err = io.Copy(buf, gz); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (u *Updater) fetch(url string) (io.ReadCloser, error) {
	if u.Requester == nil {
		return defaultHTTPRequester.Fetch(url)
	}

	readCloser, err := u.Requester.Fetch(url)
	if err != nil {
		return nil, err
	}

	if readCloser == nil {
		return nil, fmt.Errorf("fetch was expected to return non-nil ReadCloser")
	}

	return readCloser, nil
}

func (u *Updater) getPlat() string {
	arch := getArch()
	switch arch {
	case "aarch64":
		arch = "arm64"
	case "x86_64":
		arch = "amd64"
	}
	return runtime.GOOS + "_" + arch
}

func getArch() string {
	var armPattern = regexp.MustCompile(`^(?i)(armv?[0-9]{1,2})`)
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		if runtime.GOARCH == "arm" {
			return runtime.GOARCH + "v5"
		}
	}
	machine := make([]byte, 0, 65)
	for _, c := range uname.Machine {
		if c == 0 {
			break
		}
		machine = append(machine, byte(c))
	}
	arch := armPattern.FindString(string(machine))
	if arch != "" {
		return arch
	}
	return string(machine)
}
