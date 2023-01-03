package truststore

import (
	"crypto/x509"
	"fmt"
	"os/exec"
)

type Store struct {
	CAROOT   string
	RootName string

	CAUniqueName    func(caCert *x509.Certificate) string
	CommandWithSudo func(cmd ...string) *exec.Cmd

	PathExists   func(path string) bool
	BinaryExists func(name string) bool
}

func fatalErr(err error, msg string) error {
	return fmt.Errorf("ERROR: %s: %w", msg, err)
}

func fatalCmdErr(err error, cmd string, out []byte) error {
	return fmt.Errorf("ERROR: failed to execute \"%s\": %w\n\n%s\n", cmd, err, out)
}

type Warning error

func warnErr(format string, a ...any) error {
	return Warning(fmt.Errorf(format, a...))
}
