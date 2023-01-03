// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
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
	case s.BinaryExists("apt"):
		CertutilInstallHelp = "apt install libnss3-tools"
	case s.BinaryExists("yum"):
		CertutilInstallHelp = "yum install nss-tools"
	case s.BinaryExists("zypper"):
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

func (s *Store) systemTrustFilename(caCert *x509.Certificate) string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(s.CAUniqueName(caCert), " ", "_", -1))
}

func (s *Store) InstallPlatform(caCert *x509.Certificate) (bool, error) {
	s.InitPlatform()

	if SystemTrustCommand == nil {
		log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", NSSBrowsers)
		log.Printf("You can also manually install the root certificate at %q.", filepath.Join(s.CAROOT, s.RootName))
		return false, nil
	}

	cert, err := ioutil.ReadFile(filepath.Join(s.CAROOT, s.RootName))
	if err != nil {
		return false, fatalErr(err, "failed to read root certificate")
	}

	cmd := s.CommandWithSudo("tee", s.systemTrustFilename(caCert))
	cmd.Stdin = bytes.NewReader(cert)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fatalCmdErr(err, "tee", out)
	}

	cmd = s.CommandWithSudo(SystemTrustCommand...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fatalCmdErr(err, strings.Join(SystemTrustCommand, " "), out)
	}

	return true, nil
}

func (s *Store) UninstallPlatform(caCert *x509.Certificate) (bool, error) {
	s.InitPlatform()

	if SystemTrustCommand == nil {
		return false, nil
	}

	cmd := s.CommandWithSudo("rm", "-f", s.systemTrustFilename(caCert))
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fatalCmdErr(err, "rm", out)
	}

	// We used to install under non-unique filenames.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if s.PathExists(legacyFilename) {
		cmd := s.CommandWithSudo("rm", "-f", legacyFilename)
		if out, err := cmd.CombinedOutput(); err != nil {
			return false, fatalCmdErr(err, "rm (legacy filename)", out)
		}
	}

	cmd = s.CommandWithSudo(SystemTrustCommand...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fatalCmdErr(err, strings.Join(SystemTrustCommand, " "), out)
	}

	return true, nil
}
