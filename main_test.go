package main

import (
	"os"
	"strings"
	"testing"
)

func TestFindModuleForSymbol(t *testing.T) {
	tests := []struct {
		symbol      string
		modules     []string
		expected    string
		description string
	}{
		// Test module matching (longest first)
		{"github.com/gorilla/mux.NewRouter", []string{"github.com/gorilla/mux"}, "github.com/gorilla/mux", "exact module match"},
		{"github.com/gorilla/mux.(*Router).Handle", []string{"github.com/gorilla/mux"}, "github.com/gorilla/mux", "module with method receiver"},
		{"github.com/user/pkg/subpkg.Function", []string{"github.com/user/pkg"}, "github.com/user/pkg", "module with subpackage"},

		// Test main module subpackages
		{"github.com/gohugoio/hugo/common/hstrings.Truncate", []string{"github.com/gohugoio/hugo", "github.com/spf13/cobra"}, "github.com/gohugoio/hugo", "main module subpackage"},

		// Test stdlib packages
		{"runtime.main", []string{}, "runtime", "stdlib package"},
		{"encoding/json.Marshal", []string{}, "encoding/json", "stdlib package with slash"},
		{"strings.Builder.grow", []string{}, "strings", "stdlib with type method"},
		{"bytes.Buffer.WriteByte", []string{}, "bytes", "stdlib with type method"},

		// Test main package
		{"main.main", []string{}, "main", "main package"},

		// Test compiler-generated patterns to skip
		{"type:.eq.debug/elf", []string{}, "", "type: prefix skipped"},
		{"go.shape.string", []string{}, "", "go. prefix skipped"},

		// Test generic instantiations - stdlib
		{"slices.partitionCmpFunc[go.shape", []string{}, "slices", "stdlib with generic suffix"},
		{"maps.Clone[go.shape.int,go.shape.string]", []string{}, "maps", "stdlib with multiple generic params"},

		// Test generic instantiations - external
		{"github.com/spf13/cast.toUnsignedNumberE[go.shape", []string{"github.com/spf13/cast"}, "github.com/spf13/cast", "external module with generic suffix"},

		// Test domain-based packages with dots
		{"google.golang.org/protobuf/internal/detrand.init", []string{"google.golang.org/protobuf"}, "google.golang.org/protobuf", "domain with dots"},

		// Test .init functions
		{"github.com/gohugoio/localescompressed.init", []string{"github.com/gohugoio/localescompressed"}, "github.com/gohugoio/localescompressed", "module with .init"},
		{"github.com/gohugoio/localescompressed.init.0.func1", []string{"github.com/gohugoio/localescompressed"}, "github.com/gohugoio/localescompressed", "module with .init.0.func1"},

		// Test other (unrecognized)
		{"unicode.map", []string{}, "unicode", "stdlib base package"},
		{"unknown/package.Function", []string{}, "other", "unrecognized package"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := findModuleForSymbol(tt.symbol, tt.modules)
			if result != tt.expected {
				t.Errorf("findModuleForSymbol(%q, %v) = %q, want %q", tt.symbol, tt.modules, result, tt.expected)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		size     int64
		expected string
	}{
		{100, "100 B"},
		{1024, "1.00 KB"},
		{2048, "2.00 KB"},
		{1024 * 1024, "1.00 MB"},
		{1024*1024 + 512*1024, "1.50 MB"},
		{5367, "5.24 KB"},
	}

	for _, tt := range tests {
		result := formatSize(tt.size)
		if result != tt.expected {
			t.Errorf("formatSize(%d) = %q, want %q", tt.size, result, tt.expected)
		}
	}
}

func TestTruncatePackageName(t *testing.T) {
	tests := []struct {
		name     string
		maxLen   int
		expected string
	}{
		{"github.com/user/repo", 30, "github.com/user/repo"},
		{"github.com/user/repo", 10, "github...."},
		{"short", 10, "short"},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		result := truncatePackageName(tt.name, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncatePackageName(%q, %d) = %q, want %q", tt.name, tt.maxLen, result, tt.expected)
		}
	}
}

func TestGenerateSVGTreemap(t *testing.T) {
	// Create a sample report
	report := &DependencyReport{
		TotalSize: 1024 * 1024, // 1 MB
		Packages: map[string]*PackageSize{
			"github.com/user/repo": {Code: 512 * 1024}, // 512 KB
			"stdlib/package":       {Code: 256 * 1024}, // 256 KB
			"another/package":      {Code: 256 * 1024}, // 256 KB
		},
		ModulePaths: []string{"github.com/user/repo"},
	}

	// Create a temporary file
	tmpFile := t.TempDir() + "/test.svg"

	// Generate SVG
	err := generateSVGTreemap(report, tmpFile, "./testbinary")
	if err != nil {
		t.Fatalf("generateSVGTreemap failed: %v", err)
	}

	// Verify file was created
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("SVG file not created: %v", err)
	}

	// Verify file has content
	if info.Size() == 0 {
		t.Error("SVG file is empty")
	}

	// Read and verify basic SVG structure
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read SVG file: %v", err)
	}

	contentStr := string(content)

	// Check for SVG tag
	if !strings.Contains(contentStr, "<svg") {
		t.Error("SVG file missing <svg> tag")
	}

	// Check for title with binary name and size
	if !strings.Contains(contentStr, "./testbinary") {
		t.Error("SVG file missing binary name in title")
	}
	if !strings.Contains(contentStr, "1.00 MB") {
		t.Error("SVG file missing total size in title")
	}
}

func TestGenerateSVGTreemapEmptyReport(t *testing.T) {
	report := &DependencyReport{
		TotalSize: 0,
		Packages:  map[string]*PackageSize{},
	}

	tmpFile := t.TempDir() + "/empty.svg"
	err := generateSVGTreemap(report, tmpFile, "./emptybinary")

	if err == nil {
		t.Error("Expected error for empty report, got nil")
	}
}
