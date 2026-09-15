//go:build !linux

package netns

func Available() bool { return false }

func Launch(Options) (int, error) { return 1, ErrUnsupported }

func RunHelper([]string) int { return 1 }
