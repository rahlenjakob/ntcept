//go:build !darwin

package pftun

func RunHelper([]string) int { return 1 }

func Install(bool) error { return ErrUnsupported }
func Uninstall() error   { return ErrUnsupported }
func Installed() bool    { return false }

func InstallState() (bool, string) { return false, "the pf attach is macOS-only" }
