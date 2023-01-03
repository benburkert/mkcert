// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	hasJava    bool
	hasKeytool bool

	javaHome    string
	cacertsPath string
	keytoolPath string
	storePass   string = "changeit"
)

var initJavaOnce sync.Once

func (s *Store) InitJava() {
	initJavaOnce.Do(func() {
		if runtime.GOOS == "windows" {
			keytoolPath = filepath.Join("bin", "keytool.exe")
		} else {
			keytoolPath = filepath.Join("bin", "keytool")
		}

		if v := os.Getenv("JAVA_HOME"); v != "" {
			hasJava = true
			javaHome = v

			if s.PathExists(filepath.Join(v, keytoolPath)) {
				hasKeytool = true
				keytoolPath = filepath.Join(v, keytoolPath)
			}

			if s.PathExists(filepath.Join(v, "lib", "security", "cacerts")) {
				cacertsPath = filepath.Join(v, "lib", "security", "cacerts")
			}

			if s.PathExists(filepath.Join(v, "jre", "lib", "security", "cacerts")) {
				cacertsPath = filepath.Join(v, "jre", "lib", "security", "cacerts")
			}
		}
	})
}

func (s *Store) HasJava() bool {
	s.InitJava()
	return hasJava
}

func (s *Store) HasKeytool() bool {
	s.InitJava()
	return hasKeytool
}

func (s *Store) CheckJava(ca *CA) (bool, error) {
	if !hasKeytool {
		return false, nil
	}

	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(c *x509.Certificate, h hash.Hash, keytoolOutput []byte) bool {
		h.Write(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	args := []string{
		"-list",
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}

	keytoolOutput, err := s.SysFS.Exec(s.SysFS.Command(keytoolPath, args...))
	if err != nil {
		return false, fatalCmdErr(err, "keytool -list", keytoolOutput)
	}

	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// pre-Java 9 uses SHA1 fingerprints
	s1, s256 := sha1.New(), sha256.New()
	return exists(ca.Certificate, s1, keytoolOutput) || exists(ca.Certificate, s256, keytoolOutput), nil
}

func (s *Store) InstallJava(ca *CA) (bool, error) {
	args := []string{
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", filepath.Join(s.CAROOT, ca.FileName),
		"-alias", ca.UniqueName,
	}

	if out, err := s.execKeytool(s.SysFS.Command(keytoolPath, args...)); err != nil {
		return false, fatalCmdErr(err, "keytool -importcert", out)
	}
	return true, nil
}

func (s *Store) UninstallJava(ca *CA) (bool, error) {
	args := []string{
		"-delete",
		"-alias", ca.UniqueName,
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}
	out, err := s.execKeytool(s.SysFS.Command(keytoolPath, args...))
	if bytes.Contains(out, []byte("does not exist")) {
		return false, nil // cert didn't exist
	}
	if err != nil {
		return false, fatalCmdErr(err, "keytool -delete", out)
	}
	return true, nil
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func (s *Store) execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := s.SysFS.Exec(cmd)
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		cmd = s.SysFS.Command(cmd.Args[0], cmd.Args[1:]...)
		cmd.Env = []string{
			"JAVA_HOME=" + javaHome,
		}
		return s.SysFS.SudoExec(cmd)
	}
	return out, err
}
