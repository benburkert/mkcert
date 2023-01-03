package truststore

import (
	"crypto/x509"
	"fmt"
)

type CA struct {
	*x509.Certificate

	FileName   string
	UniqueName string
}

type Store struct {
	CAROOT string

	SysFS CmdFS

	PathExists func(path string) bool
}

func (s *Store) binaryExists(name string) bool {
	_, err := s.SysFS.LookPath(name)
	return err == nil
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
