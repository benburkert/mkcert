// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package main

import (
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"

	"golang.org/x/net/idna"

	"filippo.io/mkcert/truststore"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-CAROOT
	    Print the CA certificate and key storage location.

	$CAROOT (environment variable)
	    Set the CA certificate and key storage location. (This allows
	    maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	if len(os.Args) == 1 {
		fmt.Print(shortUsage)
		return
	}
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}

	rootFS := truststore.RootFS()
	rootDir := getCAROOT()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalln("ERROR: can't get user's home directory: " + err.Error())
	}

	var javaStore *truststore.Java
	if javaHomeDir := os.Getenv("JAVA_HOME"); javaHomeDir != "" {
		javaStore = &truststore.Java{
			RootDir:     rootDir,
			HomeDir:     homeDir,
			JavaHomeDir: javaHomeDir,
			StorePass:   "changeit",

			DataFS: rootFS,
			SysFS:  rootFS,
		}
	}

	(&mkcert{
		Store: &truststore.Store{
			CAROOT: rootDir,
			HOME:   homeDir,

			DataFS: rootFS,
			SysFS:  rootFS,
		},

		Java: javaStore,
		NSS: &truststore.NSS{
			RootDir: rootDir,
			HomeDir: homeDir,

			DataFS: rootFS,
			SysFS:  rootFS,
		},
		Platform: &truststore.Platform{
			RootDir: rootDir,
			HomeDir: homeDir,

			DataFS: rootFS,
			SysFS:  rootFS,
		},

		installMode: *installFlag, uninstallMode: *uninstallFlag, csrPath: *csrFlag,
		pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, client: *clientFlag,
		certFile: *certFileFlag, keyFile: *keyFileFlag, p12File: *p12FileFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

type mkcert struct {
	*truststore.Store

	Java     *truststore.Java
	NSS      *truststore.NSS
	Platform *truststore.Platform

	installMode, uninstallMode bool
	pkcs12, ecdsa, client      bool
	keyFile, certFile, p12File string
	csrPath                    string

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	ca     *truststore.CA

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run(args []string) {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	m.ca = &truststore.CA{
		Certificate: m.caCert,
		FileName:    rootName,
		UniqueName:  caUniqueName(m.caCert),
	}

	if m.installMode {
		m.install()
		if len(args) == 0 {
			return
		}
	} else if m.uninstallMode {
		m.uninstall()
		return
	} else {
		var warning bool
		if storeEnabled("system") && logErr(m.Platform.Check()) && !m.checkPlatform() {
			warning = true
			log.Println("Note: the local CA is not installed in the system trust store.")
		}
		if storeEnabled("nss") && ignoreErr(m.NSS.Check()) && !logErr(m.NSS.CheckCA(m.ca)) {
			warning = true
		}
		if storeEnabled("java") && m.Java != nil && !logErr(m.Java.CheckCA(m.ca)) {
			warning = true
			log.Println("Note: the local CA is not installed in the Java trust store.")
		}
		if warning {
			log.Println("Run \"mkcert -install\" for certificates to be trusted automatically ⚠️")
		}
	}

	if m.csrPath != "" {
		m.makeCertFromCSR()
		return
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func getCAROOT() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

func (m *mkcert) install() {
	if storeEnabled("system") {
		if m.checkPlatform() {
			log.Print("The local CA is already installed in the system trust store! 👍")
		} else {
			if logErr(m.Platform.InstallCA(m.ca)) {
				log.Print("The local CA is now installed in the system trust store! ⚡️")
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if storeEnabled("nss") && ignoreErr(m.NSS.Check()) {
		if logErr(m.NSS.CheckCA(m.ca)) {
			log.Printf("The local CA is already installed in the %s trust store! 👍", m.NSS.Browsers())
		} else {
			if logErr(m.NSS.InstallCA(m.ca)) {
				log.Printf("The local CA is now installed in the %s trust store (requires browser restart)! 🦊", m.NSS.Browsers())
			}
		}
	}
	if storeEnabled("java") && m.Java != nil {
		if ignoreErr(m.Java.CheckCA(m.ca)) {
			log.Println("The local CA is already installed in Java's trust store! 👍")
		} else {
			if logErr(m.Java.InstallCA(m.ca)) {
				log.Println("The local CA is now installed in Java's trust store! ☕️")
			}
		}
	}
	log.Print("")
}

func (m *mkcert) uninstall() {
	if storeEnabled("nss") && ignoreErr(m.NSS.Check()) {
		logErr(m.NSS.UninstallCA(m.ca))
	}
	if storeEnabled("java") && m.Java != nil {
		logErr(m.Java.UninstallCA(m.ca))
	}

	if storeEnabled("system") && logErr(m.Platform.UninstallCA(m.ca)) {
		log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
		log.Print("")
	} else if storeEnabled("nss") && ignoreErr(m.NSS.Check()) {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", m.NSS.Browsers())
		log.Print("")
	}
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.ca.Certificate.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func logErr[T any](v T, err error) T {
	var terr truststore.Error
	if errors.As(err, &terr) {
		if w := terr.Warning; w != nil {
			logWarning(w, terr.Op)
		}
		return logErr(v, terr.Fatal)
	}
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	return v
}

func logWarning(err error, op truststore.Op) {
	var exitErr *exec.ExitError

	switch err := err.(type) {
	case truststore.NSSError:
		switch {
		case errors.As(err.Err, &exitErr):
			switch op {
			case truststore.OpCheck:
				log.Printf("Note: the local CA is not installed in the %s trust store.", err.NSSBrowsers)
			default:
				panic("unhandled nss exit error operation warning")
			}
		case errors.Is(err.Err, truststore.ErrNoCertutil):
			switch op {
			case truststore.OpInstall:
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s! ⚠️`, err.NSSBrowsers)
				log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, err.CertutilInstallHelp)
			case truststore.OpUninstall:
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, err.NSSBrowsers)
				log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, err.CertutilInstallHelp)
			default:
				panic("unhandled nss no certutil operation warning")
			}
		case errors.Is(err.Err, truststore.ErrNoNSS):
			log.Printf(`Note: %s support is not available on your platform. ℹ️`, err.NSSBrowsers)
		case errors.Is(err.Err, truststore.ErrNoNSSDB):
			log.Printf("ERROR: no %s security databases found", err.NSSBrowsers)
		default:
			panic("unhandled nss warning")
		}
	case truststore.PlatformError:
		switch {
		case errors.Is(err.Err, truststore.ErrUnsupportedDistro):
			log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", err.NSSBrowsers)
			log.Printf("You can also manually install the root certificate at %q.", err.RootCA)
		default:
			panic("unhandled platform warning")
		}
	default:
		switch {
		case errors.Is(err, truststore.ErrNoKeytool):
			switch op {
			case truststore.OpInstall:
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
			case truststore.OpUninstall:
				log.Print("")
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
				log.Print("")
			default:
				panic("unhandled java no keytool operation warning")
			}
		case errors.Is(err, truststore.ErrNoSudo):
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️`)
		default:
			panic("unhandled warning")
		}
	}
}

func ignoreErr[T any](v T, err error) T { return v }

func caUniqueName(caCert *x509.Certificate) string {
	return "mkcert development CA " + caCert.SerialNumber.String()
}
