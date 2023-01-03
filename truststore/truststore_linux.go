// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var (
	FirefoxProfiles = []string{os.Getenv("HOME") + "/.mozilla/firefox/*",
		os.Getenv("HOME") + "/snap/firefox/common/.mozilla/firefox/*"}
	NSSBrowsers = "Firefox and/or Chrome/Chromium"

	SystemTrustFilename string
	SystemTrustCommand  []string
	CertutilInstallHelp string
)

func (s *Store) InitPlatform() {
	switch {
	case s.binaryExists("apt"):
		CertutilInstallHelp = "apt install libnss3-tools"
	case s.binaryExists("yum"):
		CertutilInstallHelp = "yum install nss-tools"
	case s.binaryExists("zypper"):
		CertutilInstallHelp = "zypper install mozilla-nss-tools"
	}
	if s.PathExists("/etc/pki/ca-trust/source/anchors/") {
		SystemTrustFilename = "/etc/pki/ca-trust/source/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	} else if s.PathExists("/usr/local/share/ca-certificates/") {
		SystemTrustFilename = "/usr/local/share/ca-certificates/%s.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	} else if s.PathExists("/etc/ca-certificates/trust-source/anchors/") {
		SystemTrustFilename = "/etc/ca-certificates/trust-source/anchors/%s.crt"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	} else if s.PathExists("/usr/share/pki/trust/anchors") {
		SystemTrustFilename = "/usr/share/pki/trust/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-certificates"}
	}
}

func (s *Store) systemTrustFilename(ca *CA) string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(ca.UniqueName, " ", "_", -1))
}

func (s *Store) InstallPlatform(ca *CA) (bool, error) {
	s.InitPlatform()

	if SystemTrustCommand == nil {
		msg := fmt.Sprintf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.\n", NSSBrowsers)
		msg += fmt.Sprintf("You can also manually install the root certificate at %q.", filepath.Join(s.CAROOT, ca.FileName))
		return false, warnErr(msg)
	}

	cert, err := ioutil.ReadFile(filepath.Join(s.CAROOT, ca.FileName))
	if err != nil {
		return false, fatalErr(err, "failed to read root certificate")
	}

	cmd := s.SysFS.Command("tee", s.systemTrustFilename(ca))
	cmd.Stdin = bytes.NewReader(cert)
	if out, err := s.SysFS.SudoExec(cmd); err != nil {
		return false, fatalCmdErr(err, "tee", out)
	}

	if out, err := s.SysFS.SudoExec(s.SysFS.Command(SystemTrustCommand[0], SystemTrustCommand[1:]...)); err != nil {
		return false, fatalCmdErr(err, strings.Join(SystemTrustCommand, " "), out)
	}

	return true, nil
}

func (s *Store) UninstallPlatform(ca *CA) (bool, error) {
	s.InitPlatform()

	if SystemTrustCommand == nil {
		return false, nil
	}

	cmd := s.SysFS.Command("rm", "-f", s.systemTrustFilename(ca))
	if out, err := s.SysFS.SudoExec(cmd); err != nil {
		return false, fatalCmdErr(err, "rm", out)
	}

	// We used to install under non-unique filenames.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if s.PathExists(legacyFilename) {
		cmd := s.SysFS.Command("rm", "-f", legacyFilename)
		if out, err := s.SysFS.SudoExec(cmd); err != nil {
			return false, fatalCmdErr(err, "rm (legacy filename)", out)
		}
	}

	cmd = s.SysFS.Command(SystemTrustCommand[0], SystemTrustCommand[1:]...)
	if out, err := s.SysFS.SudoExec(cmd); err != nil {
		return false, fatalCmdErr(err, strings.Join(SystemTrustCommand, " "), out)
	}

	return true, nil
}
