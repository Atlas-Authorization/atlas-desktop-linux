package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Store keeps the device key, the bundle MAC key, the cached gate state and the offline state in one directory that only the
// service account (root in production) may touch. Every read re-checks ownership and mode; a loose file is an error, not a warning.
type Store struct{ Dir string }

func NewStore(dir string) *Store { return &Store{Dir: dir} }

// checkOwned: owned by the effective user and not writable by group or others. A directory must also not be readable by others
// when secret is true.
func checkOwned(path string, secret bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not owned by the service account", path)
	}
	bad := os.FileMode(0o022)
	if secret {
		bad = 0o077
	}
	if st.Mode().Perm()&bad != 0 {
		return fmt.Errorf("%s has loose permissions %o", path, st.Mode().Perm())
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".atlas-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) ensure() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return checkOwned(s.Dir, true)
}

func (s *Store) Get(name string) ([]byte, bool) {
	p := filepath.Join(s.Dir, name)
	if checkOwned(s.Dir, true) != nil || checkOwned(p, true) != nil {
		return nil, false
	}
	b, err := os.ReadFile(p)
	return b, err == nil
}

func (s *Store) Set(name string, data []byte) error {
	if err := s.ensure(); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.Dir, name), data, 0o600)
}

func (s *Store) Delete(name string) { _ = os.Remove(filepath.Join(s.Dir, name)) }

func (s *Store) Load(name string, v any) bool {
	b, ok := s.Get(name)
	return ok && json.Unmarshal(b, v) == nil
}

func (s *Store) Save(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Set(name, b)
}

// Lock serialises read-modify-write of the offline state across concurrent logins (two ssh sessions, sudo in a script).
func (s *Store) Lock() (unlock func(), err error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

var errNoKey = errors.New("no device key")
