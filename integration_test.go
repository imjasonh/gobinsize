package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNotableBinaries builds and analyzes notable Go project binaries
func TestNotableBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Build gobinsize first
	cmd := exec.Command("go", "build", "-o", "gobinsize", ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build gobinsize: %v", err)
	}
	defer os.Remove("gobinsize")

	binDir := t.TempDir()

	projects := []struct {
		name      string
		repo      string
		buildCmd  []string
		binaryLoc string
	}{
		{
			name:      "hugo",
			repo:      "https://github.com/gohugoio/hugo.git",
			buildCmd:  []string{"go", "build", "-o", "hugo"},
			binaryLoc: "hugo",
		},
		{
			name:      "terraform",
			repo:      "https://github.com/hashicorp/terraform.git",
			buildCmd:  []string{"go", "build", "-o", "terraform"},
			binaryLoc: "terraform",
		},
	}

	for _, proj := range projects {
		proj := proj // capture range variable
		t.Run(proj.name, func(t *testing.T) {
			t.Parallel()
			projectDir := filepath.Join(binDir, proj.name+"-src")

			// Clone the repository
			t.Logf("Cloning %s...", proj.name)
			cloneCmd := exec.Command("git", "clone", "--depth", "1", proj.repo, projectDir)
			if output, err := cloneCmd.CombinedOutput(); err != nil {
				t.Logf("Clone output: %s", output)
				t.Skipf("Failed to clone %s (may be due to network): %v", proj.name, err)
				return
			}

			// Build the binary
			t.Logf("Building %s...", proj.name)
			buildCmd := exec.Command(proj.buildCmd[0], proj.buildCmd[1:]...)
			buildCmd.Dir = projectDir
			if output, err := buildCmd.CombinedOutput(); err != nil {
				t.Logf("Build output: %s", output)
				t.Skipf("Failed to build %s: %v", proj.name, err)
				return
			}

			binaryPath := filepath.Join(projectDir, proj.binaryLoc)
			if _, err := os.Stat(binaryPath); err != nil {
				t.Fatalf("Binary not found at %s: %v", binaryPath, err)
			}

			// Analyze with gobinsize
			t.Logf("Analyzing %s with gobinsize...", proj.name)
			analyzeCmd := exec.Command("./gobinsize", binaryPath)
			output, err := analyzeCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to analyze %s: %v\nOutput: %s", proj.name, err, output)
			}

			// Log the output
			t.Logf("\n=== %s Dependency Size Report ===\n%s", proj.name, output)

			// Verify output contains expected content
			outputStr := string(output)
			if outputStr == "" {
				t.Errorf("Empty output from gobinsize for %s", proj.name)
			}
		})
	}
}
