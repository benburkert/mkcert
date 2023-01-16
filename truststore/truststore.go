package truststore

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

var (
	UnsupportedDistro = errors.New("unsupported Linux distrobution")
)

type CA struct {
	*x509.Certificate

	FileName   string
	UniqueName string
}

type Store struct {
	CAROOT string

	DataFS fs.StatFS
	SysFS  CmdFS
}

func (s *Store) binaryExists(name string) bool {
	_, err := s.SysFS.LookPath(name)
	return err == nil
}

func (s *Store) pathExists(path string) bool {
	_, err := s.DataFS.Stat(strings.Trim(path, string(os.PathSeparator)))
	return err == nil
}

func fatalErr(err error, msg string) error {
	return fmt.Errorf("%s: %w", msg, err)
}

func fatalCmdErr(err error, cmd string, out []byte) error {
	return fmt.Errorf("failed to execute \"%s\": %w\n\n%s\n", cmd, err, out)
}

type Error struct {
	Fatal   error
	Warning error
}

func (e Error) Error() string {
	if e.Fatal != nil {
		return e.Fatal.Error()
	}
	return e.Warning.Error()
}

type PlatformError struct {
	Err error

	NSSBrowsers string
	RootCA      string
}

func (e PlatformError) Error() string { return e.Err.Error() }
