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

func (s *Store) CheckJava(caCert *x509.Certificate) bool {
	if !hasKeytool {
		return false
	}

	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(c *x509.Certificate, h hash.Hash, keytoolOutput []byte) bool {
		h.Write(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	keytoolOutput, err := exec.Command(keytoolPath, "-list", "-keystore", cacertsPath, "-storepass", storePass).CombinedOutput()
	s.fatalIfCmdErr(err, "keytool -list", keytoolOutput)
	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// pre-Java 9 uses SHA1 fingerprints
	s1, s256 := sha1.New(), sha256.New()
	return exists(caCert, s1, keytoolOutput) || exists(caCert, s256, keytoolOutput)
}

func (s *Store) InstallJava(caCert *x509.Certificate) {
	args := []string{
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", filepath.Join(s.CAROOT, s.RootName),
		"-alias", s.CAUniqueName(caCert),
	}

	out, err := s.execKeytool(exec.Command(keytoolPath, args...))
	s.fatalIfCmdErr(err, "keytool -importcert", out)
}

func (s *Store) UninstallJava(caCert *x509.Certificate) {
	args := []string{
		"-delete",
		"-alias", s.CAUniqueName(caCert),
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}
	out, err := s.execKeytool(exec.Command(keytoolPath, args...))
	if bytes.Contains(out, []byte("does not exist")) {
		return // cert didn't exist
	}
	s.fatalIfCmdErr(err, "keytool -delete", out)
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func (s *Store) execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = s.CommandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{
			"JAVA_HOME=" + javaHome,
		}
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
