//go:build !darwin

package pftun

func Available() (bool, string) { return false, "the pf attach is macOS-only" }

func Launch(Options) (int, error) { return 1, ErrUnsupported }
