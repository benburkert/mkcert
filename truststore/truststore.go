package truststore

import (
	"crypto/x509"
	"os/exec"
)

type Store struct {
	CAROOT   string
	RootName string

	CAUniqueName    func(caCert *x509.Certificate) string
	CommandWithSudo func(cmd ...string) *exec.Cmd
	Fatalf          func(format string, v ...any)

	PathExists   func(path string) bool
	BinaryExists func(name string) bool
}

func (s *Store) fatalIfErr(err error, msg string) {
	if err != nil {
		s.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func (s *Store) fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		s.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}
