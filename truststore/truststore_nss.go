// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	hasNSS       bool
	hasCertutil  bool
	certutilPath string
	nssDBs       = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}
	firefoxPaths = []string{
		"/usr/bin/firefox",
		"/usr/bin/firefox-nightly",
		"/usr/bin/firefox-developer-edition",
		"/snap/firefox",
		"/Applications/Firefox.app",
		"/Applications/FirefoxDeveloperEdition.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	}
)

var initNSSOnce sync.Once

func (s *Store) InitNSS() {
	initNSSOnce.Do(func() {
		s.InitPlatform()

		allPaths := append(append([]string{}, nssDBs...), firefoxPaths...)
		for _, path := range allPaths {
			if s.PathExists(path) {
				hasNSS = true
				break
			}
		}

		switch runtime.GOOS {
		case "darwin":
			switch {
			case s.BinaryExists("certutil"):
				certutilPath, _ = exec.LookPath("certutil")
				hasCertutil = true
			case s.BinaryExists("/usr/local/opt/nss/bin/certutil"):
				// Check the default Homebrew path, to save executing Ruby. #135
				certutilPath = "/usr/local/opt/nss/bin/certutil"
				hasCertutil = true
			default:
				out, err := exec.Command("brew", "--prefix", "nss").Output()
				if err == nil {
					certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
					hasCertutil = s.PathExists(certutilPath)
				}
			}

		case "linux":
			if hasCertutil = s.BinaryExists("certutil"); hasCertutil {
				certutilPath, _ = exec.LookPath("certutil")
			}
		}
	})
}

func (s *Store) HasNSS() bool {
	s.InitNSS()
	return hasNSS
}

func (s *Store) HasCertutil() bool {
	s.InitNSS()
	return hasCertutil
}

func (s *Store) CheckNSS(caCert *x509.Certificate) (bool, error) {
	if !hasCertutil {
		return false, nil
	}
	count, err := s.forEachNSSProfile(func(profile string) error {
		return exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", s.CAUniqueName(caCert)).Run()
	})
	return count != 0 && err == nil, nil
}

func (s *Store) InstallNSS(caCert *x509.Certificate) (bool, error) {
	count, err := s.forEachNSSProfile(func(profile string) error {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", s.CAUniqueName(caCert), "-i", filepath.Join(s.CAROOT, s.RootName))
		if out, err := s.execCertutil(cmd); err != nil {
			return fatalCmdErr(err, "certutil -A -d "+profile, out)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, warnErr("ERROR: no %s security databases found", NSSBrowsers)
	}
	if ok, _ := s.CheckNSS(caCert); !ok {
		msg := fmt.Sprintf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎\n", NSSBrowsers)
		msg += fmt.Sprintf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
		return false, warnErr(msg)
	}
	return true, nil
}

func (s *Store) UninstallNSS(caCert *x509.Certificate) (bool, error) {
	_, err := s.forEachNSSProfile(func(profile string) error {
		if exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", s.CAUniqueName(caCert)).Run() != nil {
			return nil
		}

		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", s.CAUniqueName(caCert))
		if out, err := s.execCertutil(cmd); err != nil {
			return fatalCmdErr(err, "certutil -D -d "+profile, out)
		}
		return nil
	})
	return err == nil, err
}

// execCertutil will execute a "certutil" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func (s *Store) execCertutil(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = s.CommandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		out, err = cmd.CombinedOutput()
	}
	return out, err
}

func (s *Store) forEachNSSProfile(f func(profile string) error) (found int, err error) {
	var profiles []string
	profiles = append(profiles, nssDBs...)
	for _, ff := range FirefoxProfiles {
		pp, _ := filepath.Glob(ff)
		profiles = append(profiles, pp...)
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if s.PathExists(filepath.Join(profile, "cert9.db")) {
			if err := f("sql:" + profile); err != nil {
				return 0, err
			}
			found++
		} else if s.PathExists(filepath.Join(profile, "cert8.db")) {
			if err := f("dbm:" + profile); err != nil {
				return 0, err
			}
			found++
		}
	}
	return
}
