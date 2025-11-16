package main

import (
	"testing"
)

func TestGetPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com/gorilla/mux.NewRouter", "github.com/gorilla/mux"},
		{"github.com/gorilla/mux.(*Router).Handle", "github.com/gorilla/mux"},
		{"runtime.main", "runtime"},
		{"type:.eq.debug/elf", ""},
		{"main.main", "main"},
		{"github.com/user/pkg/subpkg.Function", "github.com/user/pkg/subpkg"},
		{"go.shape.string", "go.shape"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := getPackageName(tt.input)
			if result != tt.expected {
				t.Errorf("getPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsExternalDependency(t *testing.T) {
	tests := []struct {
		pkgName  string
		expected bool
	}{
		{"github.com/gorilla/mux", true},
		{"github.com/user/repo", true},
		{"golang.org/x/crypto", true},
		{"gopkg.in/yaml.v2", true},
		{"go.uber.org/zap", true},
		{"runtime", false},
		{"main", false},
		{"sync", false},
		{"internal/cpu", false},
		{"debug/elf", false},
		{"net/http", false},
		{"crypto/tls", false},
		{"encoding/json", false},
		{"type:.eq.net/http", false},
		{"go.shape.string", false},
		{"vendor/golang.org/x/sys/cpu", false},
		{"slices", false},
	}

	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			result := isExternalDependency(tt.pkgName)
			if result != tt.expected {
				t.Errorf("isExternalDependency(%q) = %v, want %v", tt.pkgName, result, tt.expected)
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
