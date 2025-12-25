//go:build !covflush

package main

// flushCoverage is a no-op unless built with -tags=covflush.
func flushCoverage() {}


