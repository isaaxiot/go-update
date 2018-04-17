package update

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	openFile = os.OpenFile
)

type rollbackErr struct {
	error             // original error
	rollbackErr error // error encountered while rolling back
}

type Update struct {
	// TargetPath defines the path to the file to update.
	// The emptry string means 'the executable file of the running program'.
	TargetPath string

	// Create TargetPath replacement with this file mode. If zero, defaults to 0755.
	TargetMode os.FileMode

	// Checksum of the new binary to verify against. If nil, no checksum or signature verification is done.
	Checksum []byte

	// Public key to use for signature verification. If nil, no signature verification is done.
	PublicKey crypto.PublicKey

	// Signature to verify the updated file. If nil, no signature verification is done.
	Signature []byte

	// Pluggable signature verification algorithm. If nil, ECDSA is used.
	Verifier Verifier

	// Use this hash function to generate the checksum. If not set, SHA1 is used.
	Hash crypto.Hash

	// If nil, treat the update as a complete replacement for the contents of the file at TargetPath.
	// If non-nil, treat the update contents as a patch and use this object to apply the patch.
	Patcher Patcher

	// Store the old executable file at this path after a successful update.
	// The empty string means the old executable file will be removed after the update.
	OldSavePath string
}

// Apply performs an update of the current executable (or u.TargetFile, if set) with the contents of the given io.Reader.
//
// Apply performs the following actions to ensure a safe cross-platform update:
//
// 1. If configured, applies the contents of the update io.Reader as a binary patch.
//
// 2. If configured, computes the checksum of the new executable and verifies it matches.
//
// 3. If configured, verifies the signature with a public key.
//
// 4. Creates a new file, /path/to/.target.new with the TargetMode with the contents of the updated file
//
// 5. Renames /path/to/target to /path/to/.target.old
//
// 6. Renames /path/to/.target.new to /path/to/target
//
// 7. If the final rename is successful, deletes /path/to/.target.old, returns no error. On Windows,
// the removal of /path/to/target.old always fails, so instead Apply hides the old file instead.
//
// 8. If the final rename fails, attempts to roll back by renaming /path/to/.target.old
// back to /path/to/target.
//
// If the roll back operation fails, the file system is left in an inconsistent state (betweet steps 5 and 6) where
// there is no new executable file and the old executable file could not be be moved to its original location. In this
// case you should notify the user of the bad news and ask them to recover manually. Applications can determine whether
// the rollback failed by calling RollbackError, see the documentation on that function for additional detail.
func (u *Update) Apply(update io.Reader) error {
	// validate
	verify := false
	switch {
	case u.Signature != nil && u.PublicKey != nil:
		// okay
		verify = true
	case u.Signature != nil:
		return errors.New("no public key to verify signature with")
	case u.PublicKey != nil:
		return errors.New("No signature to verify with")
	}

	// set defaults
	if u.Hash == 0 {
		u.Hash = crypto.SHA1
	}
	if u.Verifier == nil {
		u.Verifier = NewECDSAVerifier()
	}
	// get target path
	var err error
	u.TargetPath, err = u.getPath()
	if err != nil {
		return err
	}

	if u.TargetMode == 0 {
		// read mode bits from old file
		fi, err := os.Stat(u.TargetPath)
		if err != nil {
			return err
		}
		fileMode := fi.Mode()

		// set umask to 0 so that we can set mode bits properly
		oldMode := syscall.Umask(0000)
		defer syscall.Umask(oldMode)

		u.TargetMode = fileMode
	}

	var newBytes []byte
	if u.Patcher != nil {
		if newBytes, err = u.applyPatch(update); err != nil {
			return err
		}
	} else {
		// no patch to apply, go on through
		if newBytes, err = ioutil.ReadAll(update); err != nil {
			return err
		}
	}

	// verify checksum if requested
	if u.Checksum != nil {
		if err = u.verifyChecksum(newBytes); err != nil {
			return err
		}
	}

	if verify {
		if err = u.verifySignature(newBytes); err != nil {
			return err
		}
	}

	// get the directory the executable exists in
	updateDir := filepath.Dir(u.TargetPath)
	filename := filepath.Base(u.TargetPath)

	// Copy the contents of newbinary to a new executable file
	newPath := filepath.Join(updateDir, fmt.Sprintf(".%s.new", filename))
	fp, err := openFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, u.TargetMode)
	if err != nil {
		return err
	}
	os.Chmod(newPath, u.TargetMode)
	defer fp.Close()

	_, err = io.Copy(fp, bytes.NewReader(newBytes))
	if err != nil {
		return err
	}

	// if we don't call fp.Close(), windows won't let us move the new executable
	// because the file will still be "in use"
	fp.Close()

	// this is where we'll move the executable to so that we can swap in the updated replacement
	oldPath := u.OldSavePath
	removeOld := u.OldSavePath == ""
	if removeOld {
		oldPath = filepath.Join(updateDir, fmt.Sprintf(".%s.old", filename))
	}

	if err := u.sanityCheck(newPath); err != nil {
		return err
	}

	//TODO: investigate. something wrong here
	// delete any existing old exec file - this is necessary on Windows for two reasons:
	// 1. after a successful update, Windows can't remove the .old file because the process is still running
	// 2. windows rename operations fail if the destination file already exists
	// _ = os.Remove(oldPath)

	// move the existing executable to a new file in the same directory
	err = os.Rename(u.TargetPath, oldPath)
	if err != nil {
		return err
	}

	// move the new exectuable in to become the new program
	err = os.Rename(newPath, u.TargetPath)

	if err != nil {
		// move unsuccessful
		//
		// The filesystem is now in a bad state. We have successfully
		// moved the existing binary to a new location, but we couldn't move the new
		// binary to take its place. That means there is no file where the current executable binary
		// used to be!
		// Try to rollback by restoring the old binary to its original path.
		rerr := os.Rename(oldPath, u.TargetPath)
		if rerr != nil {
			return &rollbackErr{err, rerr}
		}

		return err
	}

	// move successful, remove the old binary if needed
	if removeOld {
		errRemove := os.Remove(oldPath)

		// windows has trouble with removing old binaries, so hide it instead
		if errRemove != nil {
			_ = hideFile(oldPath)
		}
	}

	return nil
}

func (u *Update) sanityCheck(newPath string) error {
	//overseer sanity check, dont replace our good binary with a non-executable file
	tokenIn := token()
	cmd := exec.Command(newPath, "validate")
	cmd.Env = append(os.Environ(), []string{"TEST_TOKEN=" + tokenIn}...)
	returned := false
	go func() {
		time.Sleep(5 * time.Second)
		if !returned {
			log.Printf("sanity check against fetched executable timed-out\n")
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}
	}()
	tokenOut, err := cmd.CombinedOutput()
	returned = true
	if err != nil {
		return fmt.Errorf("failed to run temp binary: %s (%s) output \"%s\"", err, newPath, tokenOut)
	}
	if tokenIn != strings.TrimSpace(string(tokenOut)) {
		return fmt.Errorf("sanity check failed: %s!=%s", tokenIn, string(tokenOut))
	}
	return nil
}

// RollbackError takes an error value returned by Apply and returns the error, if any,
// that occurred when attempting to roll back from a failed update. Applications should
// always call this function on any non-nil errors returned by Apply.
//
// If no rollback was needed or if the rollback was successful, RollbackError returns nil,
// otherwise it returns the error encountered when trying to roll back.
func RollbackError(err error) error {
	if err == nil {
		return nil
	}
	if rerr, ok := err.(*rollbackErr); ok {
		return rerr.rollbackErr
	}
	return nil
}

// CheckPermissions determines whether the process has the correct permissions to
// perform the requested update. If the update can proceed, it returns nil, otherwise
// it returns the error that would occur if an update were attempted.
func (u *Update) CheckPermissions() error {
	// get the directory the file exists in
	path, err := u.getPath()
	if err != nil {
		return err
	}

	fileDir := filepath.Dir(path)
	fileName := filepath.Base(path)

	// attempt to open a file in the file's directory
	newPath := filepath.Join(fileDir, fmt.Sprintf(".%s.new", fileName))
	fp, err := openFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, u.TargetMode)
	if err != nil {
		return err
	}
	fp.Close()

	_ = os.Remove(newPath)
	return nil
}

// SetPublicKeyPEM is a convenience method to set the PublicKey property
// used for checking a completed update's signature by parsing a
// Public Key formatted as PEM data.
func (u *Update) SetPublicKeyPEM(pembytes []byte) error {
	block, _ := pem.Decode(pembytes)
	if block == nil {
		return errors.New("couldn't parse PEM data")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	u.PublicKey = pub
	return nil
}

func (u *Update) getPath() (string, error) {
	if u.TargetPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}

		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return "", err
		}

		return exe, nil
	} else {
		return u.TargetPath, nil
	}
}

func (u *Update) applyPatch(patch io.Reader) ([]byte, error) {
	// open the file to patch
	old, err := os.Open(u.TargetPath)
	if err != nil {
		return nil, err
	}
	defer old.Close()

	// apply the patch
	var applied bytes.Buffer
	if err = u.Patcher.Patch(old, &applied, patch); err != nil {
		return nil, err
	}

	return applied.Bytes(), nil
}

func (u *Update) verifyChecksum(updated []byte) error {
	checksum, err := checksumFor(u.Hash, updated)
	if err != nil {
		return err
	}

	if !bytes.Equal(u.Checksum, checksum) {
		return fmt.Errorf("Updated file has wrong checksum. Expected: %x, got: %x", u.Checksum, checksum)
	}
	return nil
}

func (u *Update) verifySignature(updated []byte) error {
	checksum, err := checksumFor(u.Hash, updated)
	if err != nil {
		return err
	}
	return u.Verifier.VerifySignature(checksum, u.Signature, u.Hash, u.PublicKey)
}

func checksumFor(h crypto.Hash, payload []byte) ([]byte, error) {
	if !h.Available() {
		return nil, errors.New("requested hash function not available")
	}
	hash := h.New()
	hash.Write(payload) // guaranteed not to error
	return hash.Sum([]byte{}), nil
}

func token() string {
	buff := make([]byte, 8)
	rand.Read(buff)
	return fmt.Sprintf("%x", buff)
}
