// +build !windows

package update

import (
	"golang.org/x/sys/unix"
	"regexp"
	"runtime"
	"syscall"
)

func setUmask(mask int) int {
	return syscall.Umask(mask)
}

func unsetUmask(oldMode int) {
	syscall.Umask(oldMode)
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
