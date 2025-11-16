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
		{"go.shape.string", "go"}, // go.shape is special; would be filtered by isExternalDependency anyway
		// Test .init suffix removal
		{"github.com/gohugoio/localescompressed.init", "github.com/gohugoio/localescompressed"},
		{"github.com/gohugoio/localescompressed.init.0", "github.com/gohugoio/localescompressed"},
		{"github.com/gohugoio/localescompressed.init.1", "github.com/gohugoio/localescompressed"},
		{"some/package.init", "some/package"},
		// Test generic instantiations with [go.shape suffix
		{"slices.partitionCmpFunc[go.shape", "slices"},
		{"github.com/spf13/cast.toUnsignedNumberE[go.shape", "github.com/spf13/cast"},
		{"strings.Builder[go.shape.string]", "strings"},
		{"maps.Clone[go.shape.int,go.shape.string]", "maps"},
		// Test go: prefix patterns
		{"go:struct { github.com/gohugoio/hugo", "github.com/gohugoio/hugo"},
		{"go:itab.*os.File,io.Writer", "os"},
		{"go:itab.*bytes.Buffer,io.Writer", "bytes"},
		{"go:struct { runtime", "runtime"},
		{"go:struct { strings", "strings"},
		// Test type methods like Type.method
		{"strings.Builder.grow", "strings"},
		{"bytes.Buffer.WriteByte", "bytes"},
		{"github.com/user/pkg.MyType.Method", "github.com/user/pkg"},
		// Test runtime special cases
		{"runtime.boundsError", "runtime"},
		{"runtime.panicIndex", "runtime"},
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
		{"runtime", true},
		{"main", true},
		{"sync", true},
		{"internal/cpu", true},
		{"debug/elf", true},
		{"net/http", true},
		{"crypto/tls", true},
		{"encoding/json", true},
		{"type:.eq.net/http", true},
		{"go.shape.string", false}, // Filtered out
		{"vendor/golang.org/x/sys/cpu", true},
		{"slices", true},
		{"weak.pointer", false},  // Filtered out
		{"unique.handle", false}, // Filtered out
		{"", false},              // Empty string
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

func TestGetModuleName(t *testing.T) {
	// Test without module map (heuristic-based)
	t.Run("without module map", func(t *testing.T) {
		tests := []struct {
			pkgName  string
			expected string
		}{
			{"github.com/gorilla/mux", "github.com/gorilla/mux"},
			{"github.com/gorilla/mux/subpkg", "github.com/gorilla/mux"},
			{"github.com/user/repo/internal/pkg", "github.com/user/repo"},
			{"golang.org/x/crypto", "golang.org/x/crypto"},
			{"golang.org/x/crypto/ssh", "golang.org/x/crypto"},
			{"gopkg.in/yaml.v2", "gopkg.in/yaml.v2"},
			{"runtime", "runtime"},
			{"net/http", "net"},
			{"crypto/tls", "crypto"},
			{"encoding/json", "encoding"},
			{"type:.eq.net/http", "type:.eq.net/http"}, // type info keeps full name
			{"main", "main"},
		}

		emptyModuleMap := make(map[string]string)
		for _, tt := range tests {
			t.Run(tt.pkgName, func(t *testing.T) {
				result := getModuleName(tt.pkgName, emptyModuleMap)
				if result != tt.expected {
					t.Errorf("getModuleName(%q, emptyMap) = %q, want %q", tt.pkgName, result, tt.expected)
				}
			})
		}
	})

	// Test with module map (BuildInfo-based)
	t.Run("with module map", func(t *testing.T) {
		moduleMap := map[string]string{
			"github.com/gohugoio/localescompressed": "github.com/gohugoio/localescompressed",
			"github.com/evanw/esbuild":              "github.com/evanw/esbuild",
			"golang.org/x/text":                     "golang.org/x/text",
		}

		tests := []struct {
			pkgName  string
			expected string
		}{
			{"github.com/gohugoio/localescompressed", "github.com/gohugoio/localescompressed"},
			{"github.com/gohugoio/localescompressed/internal", "github.com/gohugoio/localescompressed"},
			{"github.com/evanw/esbuild/pkg/api", "github.com/evanw/esbuild"},
			{"golang.org/x/text/unicode", "golang.org/x/text"},
			{"unknown/package", "unknown"},
		}

		for _, tt := range tests {
			t.Run(tt.pkgName, func(t *testing.T) {
				result := getModuleName(tt.pkgName, moduleMap)
				if result != tt.expected {
					t.Errorf("getModuleName(%q, moduleMap) = %q, want %q", tt.pkgName, result, tt.expected)
				}
			})
		}
	})
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

func TestGetPackageNameRuntimeTypes(t *testing.T) {
tests := []struct {
input    string
expected string
}{
{"runtime.traceLocker.Lock", "runtime"},
{"runtime.traceLocker.Unlock", "runtime"},
{"runtime.initMetrics.compute", "runtime"},
{"runtime.traceWriter.flush", "runtime"},
{"runtime.traceAdvance.forEachP", "runtime"},
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
