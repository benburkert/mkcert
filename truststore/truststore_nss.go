// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	NoCertutil = errors.New("no certutil tooling")
	NoNSS      = errors.New("no NSS browser")
	NoNSSDB    = errors.New("no NSS database")
	UnknownNSS = errors.New("unknown NSS install") // untested

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

type NSSError struct {
	Err error

	CertutilInstallHelp string
	NSSBrowsers         string
	Operation           string
}

func (e NSSError) Error() string { return e.Err.Error() }

var initNSSOnce sync.Once

func (s *Store) InitNSS() {
	initNSSOnce.Do(func() {
		s.InitPlatform()

		allPaths := append(append([]string{}, nssDBs...), firefoxPaths...)
		for _, path := range allPaths {
			if s.pathExists(path) {
				hasNSS = true
				break
			}
		}

		switch runtime.GOOS {
		case "darwin":
			switch {
			case s.binaryExists("certutil"):
				certutilPath, _ = s.SysFS.LookPath("certutil")
				hasCertutil = true
			case s.binaryExists("/usr/local/opt/nss/bin/certutil"):
				// Check the default Homebrew path, to save executing Ruby. #135
				certutilPath = "/usr/local/opt/nss/bin/certutil"
				hasCertutil = true
			default:
				if out, err := s.SysFS.Exec(s.SysFS.Command("brew", "--prefix", "nss")); err != nil {
					certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
					hasCertutil = s.pathExists(certutilPath)
				}
			}

		case "linux":
			if hasCertutil = s.binaryExists("certutil"); hasCertutil {
				certutilPath, _ = s.SysFS.LookPath("certutil")
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

func (s *Store) CheckNSS(ca *CA) (bool, error) {
	if !hasCertutil {
		return false, nil
	}
	count, err := s.forEachNSSProfile(func(profile string) error {
		_, err := s.SysFS.Exec(s.SysFS.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", ca.UniqueName))
		return err
	})
	return count != 0 && err == nil, nil
}

func (s *Store) InstallNSS(ca *CA) (ok bool, err error) {
	if !hasCertutil {
		if CertutilInstallHelp == "" {
			return false, Error{
				Warning: NSSError{
					Err: NoNSS,

					CertutilInstallHelp: CertutilInstallHelp,
					NSSBrowsers:         NSSBrowsers,
					Operation:           "install",
				},
			}
		}
		return false, Error{
			Warning: NSSError{
				Err: NoCertutil,

				CertutilInstallHelp: CertutilInstallHelp,
				NSSBrowsers:         NSSBrowsers,
				Operation:           "install",
			},
		}
	}

	count, err := s.forEachNSSProfile(func(profile string) error {
		args := []string{
			"-A", "-d", profile,
			"-t", "C,,",
			"-n", ca.UniqueName,
			"-i", filepath.Join(s.CAROOT, ca.FileName),
		}

		if out, err := s.execCertutil(certutilPath, args...); err != nil {
			return fatalCmdErr(err, "certutil -A -d "+profile, out)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, Error{
			Warning: NSSError{
				Err: NoNSSDB,

				CertutilInstallHelp: CertutilInstallHelp,
				NSSBrowsers:         NSSBrowsers,
				Operation:           "install",
			},
		}
	}
	if ok, _ := s.CheckNSS(ca); !ok {
		return false, Error{Warning: UnknownNSS}
	}
	return true, nil
}

func (s *Store) UninstallNSS(ca *CA) (bool, error) {
	if !hasCertutil {
		if CertutilInstallHelp == "" {
			return false, Error{
				Warning: NSSError{
					Err: NoNSS,

					CertutilInstallHelp: CertutilInstallHelp,
					NSSBrowsers:         NSSBrowsers,
					Operation:           "uninstall",
				},
			}
		}
		return false, Error{
			Warning: NSSError{
				Err: NoCertutil,

				CertutilInstallHelp: CertutilInstallHelp,
				NSSBrowsers:         NSSBrowsers,
				Operation:           "uninstall",
			},
		}
	}

	_, err := s.forEachNSSProfile(func(profile string) error {
		args := []string{
			"-V", "-d", profile,
			"-u", "L",
			"-n", ca.UniqueName,
		}

		if _, err := s.SysFS.Exec(s.SysFS.Command(certutilPath, args...)); err != nil {
			return nil
		}

		args = []string{
			"-D", "-d", profile,
			"-n", ca.UniqueName,
		}

		if out, err := s.execCertutil(certutilPath, args...); err != nil {
			return fatalCmdErr(err, "certutil -D -d "+profile, out)
		}
		return nil
	})
	return err == nil, err
}

// execCertutil will execute a "certutil" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func (s *Store) execCertutil(path string, arg ...string) ([]byte, error) {
	out, err := s.SysFS.Exec(s.SysFS.Command(path, arg...))
	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		out, err = s.SysFS.SudoExec(s.SysFS.Command(path, arg...))
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
		if s.pathExists(filepath.Join(profile, "cert9.db")) {
			if err := f("sql:" + profile); err != nil {
				return 0, err
			}
			found++
		} else if s.pathExists(filepath.Join(profile, "cert8.db")) {
			if err := f("dbm:" + profile); err != nil {
				return 0, err
			}
			found++
		}
	}
	return
}
