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
		{
			name:      "cosign",
			repo:      "https://github.com/sigstore/cosign.git",
			buildCmd:  []string{"go", "build", "-o", "cosign", "./cmd/cosign"},
			binaryLoc: "cosign",
		},
		{
			name:      "gobinsize",
			repo:      "https://github.com/imjasonh/gobinsize.git",
			buildCmd:  []string{"go", "build", "-o", "gobinsize", "."},
			binaryLoc: "gobinsize",
		},
		{
			name:      "chainctl",
			repo:      "https://github.com/chainguard-dev/chainctl.git",
			buildCmd:  []string{"go", "build", "-o", "chainctl", "."},
			binaryLoc: "chainctl",
		},
		{
			name:      "docker",
			repo:      "https://github.com/docker/cli.git",
			buildCmd:  []string{"go", "build", "-o", "docker", "./cmd/docker"},
			binaryLoc: "docker",
		},
	}

	// GOOS values to test
	gooses := []string{"linux", "darwin", "windows"}

	for _, proj := range projects {
		proj := proj // capture range variable
		t.Run(proj.name, func(t *testing.T) {
			projectDir := filepath.Join(binDir, proj.name+"-src")

			// Clone the repository (once per project, not per GOOS)
			t.Logf("Cloning %s...", proj.name)
			cloneCmd := exec.Command("git", "clone", "--depth", "1", proj.repo, projectDir)
			if output, err := cloneCmd.CombinedOutput(); err != nil {
				t.Logf("Clone output: %s", output)
				t.Skipf("Failed to clone %s (may be due to network): %v", proj.name, err)
				return
			}

			// Run tests for each GOOS in parallel
			for _, goos := range gooses {
				goos := goos // capture range variable
				t.Run(goos, func(t *testing.T) {
					t.Parallel()

					// Determine binary name based on GOOS
					binaryName := proj.binaryLoc + "-" + goos
					if goos == "windows" {
						binaryName += ".exe"
					}

					// Build the binary for specific GOOS
					t.Logf("Building %s for %s...", proj.name, goos)
					buildCmd := exec.Command(proj.buildCmd[0], proj.buildCmd[1:]...)
					buildCmd.Dir = projectDir
					buildCmd.Env = append(os.Environ(), "GOOS="+goos)
					// Update the output binary name to include GOOS
					for i, arg := range buildCmd.Args {
						if arg == "-o" && i+1 < len(buildCmd.Args) {
							buildCmd.Args[i+1] = binaryName
						}
					}
					if output, err := buildCmd.CombinedOutput(); err != nil {
						t.Logf("Build output: %s", output)
						t.Skipf("Failed to build %s for %s: %v", proj.name, goos, err)
						return
					}

					binaryPath := filepath.Join(projectDir, binaryName)
					if _, err := os.Stat(binaryPath); err != nil {
						t.Fatalf("Binary not found at %s: %v", binaryPath, err)
					}

					// Analyze with gobinsize
					t.Logf("Analyzing %s (%s) with gobinsize...", proj.name, goos)
					analyzeCmd := exec.Command("./gobinsize", binaryPath)
					output, err := analyzeCmd.CombinedOutput()
					if err != nil {
						t.Fatalf("Failed to analyze %s (%s): %v\nOutput: %s", proj.name, goos, err, output)
					}

					// Log the output
					t.Logf("\n=== %s (%s) Dependency Size Report ===\n%s", proj.name, goos, output)

					// Verify output contains expected content
					outputStr := string(output)
					if outputStr == "" {
						t.Errorf("Empty output from gobinsize for %s (%s)", proj.name, goos)
					}

					// Generate SVG treemap for Linux binaries (emit into repo root)
					if goos == "linux" {
						svgPath := filepath.Join(".", proj.name+"-treemap.svg")
						t.Logf("Generating SVG treemap for %s...", proj.name)
						svgCmd := exec.Command("./gobinsize", "-svg", svgPath, binaryPath)
						svgOutput, err := svgCmd.CombinedOutput()
						if err != nil {
							t.Logf("Failed to generate SVG for %s: %v\nOutput: %s", proj.name, err, svgOutput)
						} else {
							t.Logf("SVG treemap written to %s", svgPath)
						}
					}
				})
			}
		})
	}
}
