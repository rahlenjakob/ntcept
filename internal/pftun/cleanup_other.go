//go:build !darwin

package pftun

func Cleanup() (int, error) { return 0, nil }
