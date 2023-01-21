package truststore

import (
	"path/filepath"
)

func (s *Platform) Check() (bool, error) {
	ok, err := s.check()
	if err != nil {
		err = Error{
			Op: OpCheck,

			Warning: PlatformError{
				Err: err,

				NSSBrowsers: nssBrowsers,
			},
		}
	}
	return ok, err
}

func (s *Platform) InstallCA(ca *CA) (installed bool, err error) {
	caPath := filepath.Join(s.RootDir, ca.FileName)

	if _, cerr := s.check(); cerr != nil {
		defer func() {
			err = Error{
				Op: OpInstall,

				Warning: PlatformError{
					Err: cerr,

					NSSBrowsers: nssBrowsers,
					RootCA:      caPath,
				},
			}
		}()
	}

	return s.installCA(ca)
}

func (s *Platform) UninstallCA(ca *CA) (uninstalled bool, err error) {
	caPath := filepath.Join(s.RootDir, ca.FileName)

	if _, cerr := s.check(); cerr != nil {
		defer func() {
			err = Error{
				Op: OpUninstall,

				Warning: PlatformError{
					Err: cerr,

					NSSBrowsers: nssBrowsers,
					RootCA:      caPath,
				},
			}
		}()
	}

	return s.uninstallCA(ca)
}
