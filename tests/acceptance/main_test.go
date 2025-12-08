package acceptance

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Parse flags (needed for -parallel-containers).
	flag.Parse()

	// Run tests.
	code := m.Run()

	// Cleanup container pool.
	ClosePool()

	os.Exit(code)
}
