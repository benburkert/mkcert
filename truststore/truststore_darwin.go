// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"howett.net/plist"
)

var (
	FirefoxProfiles     = []string{os.Getenv("HOME") + "/Library/Application Support/Firefox/Profiles/*"}
	CertutilInstallHelp = "brew install nss"
	NSSBrowsers         = "Firefox"
)

// https://github.com/golang/go/issues/24652#issuecomment-399826583
var trustSettings []interface{}
var _, _ = plist.Unmarshal(trustSettingsData, &trustSettings)
var trustSettingsData = []byte(`
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
`)

func (s *Store) InitPlatform() {}

func (s *Store) InstallPlatform(ca *CA) (bool, error) {
	args := []string{
		"add-trusted-cert", "-d",
		"-k", "/Library/Keychains/System.keychain",
		filepath.Join(s.CAROOT, ca.FileName),
	}
	if out, err := s.SysFS.SudoExec(s.SysFS.Command("security", args...)); err != nil {
		return false, fatalCmdErr(err, "security add-trusted-cert", out)
	}

	// Make trustSettings explicit, as older Go does not know the defaults.
	// https://github.com/golang/go/issues/24652

	plistFile, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		return false, fatalErr(err, "failed to create temp file")
	}
	defer os.Remove(plistFile.Name())

	args = []string{
		"trust-settings-export",
		"-d", plistFile.Name(),
	}
	if out, err := s.SysFS.SudoExec(s.SysFS.Command("security", args...)); err != nil {
		return false, fatalCmdErr(err, "security trust-settings-export", out)
	}

	plistData, err := ioutil.ReadFile(plistFile.Name())
	if err != nil {
		return false, fatalErr(err, "failed to read trust settings")
	}

	var plistRoot map[string]interface{}
	if _, err = plist.Unmarshal(plistData, &plistRoot); err != nil {
		return false, fatalErr(err, "failed to parse trust settings")
	}
	if plistRoot["trustVersion"].(uint64) != 1 {
		return false, fmt.Errorf("ERROR: unsupported trust settings version: %s", plistRoot["trustVersion"])
	}

	rootSubjectASN1, err := asn1.Marshal(ca.Certificate.Subject.ToRDNSequence())
	if err != nil {
		return false, fatalErr(err, "failed to marshal certificate subject")
	}

	trustList := plistRoot["trustList"].(map[string]interface{})
	for key := range trustList {
		entry := trustList[key].(map[string]interface{})
		if _, ok := entry["issuerName"]; !ok {
			continue
		}
		issuerName := entry["issuerName"].([]byte)
		if !bytes.Equal(rootSubjectASN1, issuerName) {
			continue
		}
		entry["trustSettings"] = trustSettings
		break
	}

	if plistData, err = plist.MarshalIndent(plistRoot, plist.XMLFormat, "\t"); err != nil {
		return false, fatalErr(err, "failed to serialize trust settings")
	}
	if err = ioutil.WriteFile(plistFile.Name(), plistData, 0600); err != nil {
		return false, fatalErr(err, "failed to write trust settings")
	}

	args = []string{
		"trust-settings-import",
		"-d", plistFile.Name(),
	}
	if out, err := s.SysFS.SudoExec(s.SysFS.Command("security", args...)); err != nil {
		return false, fatalCmdErr(err, "security trust-settings-import", out)
	}

	return true, nil
}

func (s *Store) UninstallPlatform(ca *CA) (bool, error) {
	args := []string{
		"remove-trusted-cert",
		"-d", filepath.Join(s.CAROOT, ca.FileName),
	}
	if out, err := s.SysFS.SudoExec(s.SysFS.Command("security", args...)); err != nil {
		return false, fatalCmdErr(err, "security remove-trusted-cert", out)
	}
	return true, nil
}
