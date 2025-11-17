package main

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

var verbose = flag.Bool("verbose", false, "enable verbose logging for debugging attribution")

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-verbose] <binary>\n", os.Args[0])
		os.Exit(1)
	}

	binaryPath := flag.Arg(0)

	report, err := analyzeBinary(binaryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing binary: %v\n", err)
		os.Exit(1)
	}

	printReport(report)
}

type DependencyReport struct {
	TotalSize   int64
	Packages    map[string]int64
	ModulePaths []string // sorted list of module paths (longest first)
}

func analyzeBinary(path string) (*DependencyReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary: %w", err)
	}
	defer f.Close()

	// Extract BuildInfo to get module dependencies
	buildInfo, err := buildinfo.ReadFile(path)
	var modulePaths []string
	if err == nil && buildInfo != nil {
		// Add the main module path first
		if buildInfo.Main.Path != "" {
			modulePaths = append(modulePaths, buildInfo.Main.Path)
		}
		// Collect module paths from dependencies
		for _, dep := range buildInfo.Deps {
			if dep != nil {
				modulePaths = append(modulePaths, dep.Path)
			}
		}
	}

	// Sort module paths by length (longest first) to ensure we match the most specific module
	sort.Slice(modulePaths, func(i, j int) bool {
		return len(modulePaths[i]) > len(modulePaths[j])
	})

	// Try all supported binary formats in order
	return tryParsers(f, modulePaths)
}

// tryParsers attempts to analyze the binary using all supported formats in order.
func tryParsers(r io.ReaderAt, modulePaths []string) (*DependencyReport, error) {
	parsers := []func(io.ReaderAt, []string) (*DependencyReport, error){
		analyzeELF,
		analyzeMachO,
		analyzePE,
	}
	for _, parser := range parsers {
		report, err := parser(r, modulePaths)
		if err == nil {
			return report, nil
		}
	}
	return nil, fmt.Errorf("unsupported binary format (not ELF, Mach-O, or PE)")
}

func analyzeELF(r io.ReaderAt, modulePaths []string) (*DependencyReport, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()

	return analyzeSymbols(elfFile, modulePaths)
}

func analyzeMachO(r io.ReaderAt, modulePaths []string) (*DependencyReport, error) {
	machoFile, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer machoFile.Close()

	return analyzeSymbolsMachO(machoFile, modulePaths)
}

func analyzePE(r io.ReaderAt, modulePaths []string) (*DependencyReport, error) {
	peFile, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	return analyzeSymbolsPE(peFile, modulePaths)
}

func analyzeSymbols(elfFile *elf.File, modulePaths []string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages:    make(map[string]int64),
		ModulePaths: modulePaths,
	}

	// Get the Go symbol table
	pclntab := elfFile.Section(".gopclntab")
	if pclntab == nil {
		return nil, fmt.Errorf("no .gopclntab section found")
	}

	pclntabData, err := pclntab.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .gopclntab: %w", err)
	}

	// Get the symtab section
	symtabSection := elfFile.Section(".gosymtab")
	if symtabSection == nil {
		// Try without .gosymtab for newer Go versions
		pcln := gosym.NewLineTable(pclntabData, elfFile.Section(".text").Addr)
		return analyzeLineTable(pcln, report)
	}

	symtabData, err := symtabSection.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .gosymtab: %w", err)
	}

	textSection := elfFile.Section(".text")
	if textSection == nil {
		return nil, fmt.Errorf("no .text section found")
	}

	pcln := gosym.NewLineTable(pclntabData, textSection.Addr)
	table, err := gosym.NewTable(symtabData, pcln)
	if err != nil {
		return nil, fmt.Errorf("failed to parse symbol table: %w", err)
	}

	// Analyze functions and their sizes
	processSymbolTable(table, modulePaths, report)

	return report, nil
}

func analyzeLineTable(pcln *gosym.LineTable, report *DependencyReport) (*DependencyReport, error) {
	// For newer Go versions without .gosymtab, we cannot perform detailed analysis
	// as we lack the function symbol information needed to attribute sizes
	return nil, fmt.Errorf("analysis not supported for binaries without .gosymtab (Go symbol table)")
}

// processSymbolTable analyzes function symbols and attributes their sizes to modules
func processSymbolTable(table *gosym.Table, modulePaths []string, report *DependencyReport) {
	for _, fn := range table.Funcs {
		pkgName := getPackageName(fn.Name)
		if pkgName != "" && isExternalDependency(pkgName) {
			moduleName := getModuleName(pkgName, modulePaths)
			report.Packages[moduleName] += int64(fn.End - fn.Entry)
			report.TotalSize += int64(fn.End - fn.Entry)
		}
	}
}

func analyzeSymbolsMachO(machoFile *macho.File, modulePaths []string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages:    make(map[string]int64),
		ModulePaths: modulePaths,
	}

	// Find the __gopclntab section
	var pclntabData []byte
	var textAddr uint64

	for _, section := range machoFile.Sections {
		if section.Name == "__gopclntab" {
			data, err := section.Data()
			if err != nil {
				return nil, err
			}
			pclntabData = data
		}
		if section.Name == "__text" {
			textAddr = section.Addr
		}
	}

	if pclntabData == nil {
		return nil, fmt.Errorf("no __gopclntab section found")
	}

	pcln := gosym.NewLineTable(pclntabData, textAddr)

	// Try to find symbol table
	var symtabData []byte
	for _, section := range machoFile.Sections {
		if section.Name == "__gosymtab" {
			data, err := section.Data()
			if err == nil {
				symtabData = data
			}
			break
		}
	}

	if symtabData == nil {
		return nil, fmt.Errorf("no __gosymtab section found")
	}

	table, err := gosym.NewTable(symtabData, pcln)
	if err == nil {
		processSymbolTable(table, modulePaths, report)
	}

	return report, nil
}

func analyzeSymbolsPE(peFile *pe.File, modulePaths []string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages:    make(map[string]int64),
		ModulePaths: modulePaths,
	}

	// Get the image base from the PE optional header
	var imageBase uint64
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	}

	// Find the .text section address (RVA) and add image base to get VMA
	var textAddr uint64
	for _, section := range peFile.Sections {
		if section.Name == ".text" || section.Name == "text" {
			textAddr = imageBase + uint64(section.VirtualAddress)
			break
		}
	}

	// Try to find .gopclntab and .gosymtab as separate sections (old Go versions)
	var pclntabData []byte
	var symtabData []byte

	for _, section := range peFile.Sections {
		if section.Name == ".gopclntab" || section.Name == "gopclntab" {
			data, err := section.Data()
			if err != nil {
				return nil, err
			}
			pclntabData = data
		}
		if section.Name == ".gosymtab" || section.Name == "gosymtab" {
			data, err := section.Data()
			if err == nil {
				symtabData = data
			}
		}
	}

	// If not found as separate sections, try to extract from runtime symbols (Go 1.16+)
	if pclntabData == nil {
		var err error
		pclntabData, symtabData, err = extractTablesFromSymbols(peFile)
		if err != nil {
			return nil, fmt.Errorf("failed to extract runtime tables: %w", err)
		}
	}

	if pclntabData == nil {
		return nil, fmt.Errorf("no pclntab data found")
	}

	pcln := gosym.NewLineTable(pclntabData, textAddr)

	// symtabData may be nil or empty for newer Go versions - gosym.NewTable can handle this
	if symtabData == nil {
		symtabData = []byte{}
	}

	table, err := gosym.NewTable(symtabData, pcln)
	if err != nil {
		return nil, fmt.Errorf("failed to create symbol table: %w", err)
	}

	processSymbolTable(table, modulePaths, report)
	return report, nil
}

const (
	// noNextSectionRVA is a sentinel value indicating no next section was found
	noNextSectionRVA uint32 = 0xFFFFFFFF
)

// extractTablesFromSymbols extracts pclntab and symtab from runtime symbols in PE files (Go 1.16+)
func extractTablesFromSymbols(peFile *pe.File) (pclntab, symtab []byte, err error) {
	var pclntabRVA, epclntabRVA, symtabRVA, esymtabRVA uint32

	// Find the runtime.pclntab, runtime.epclntab, runtime.symtab, runtime.esymtab symbols
	// Symbol values in PE are section-relative offsets, not RVAs
	// We need to add the section's VirtualAddress to get the RVA
	for _, sym := range peFile.Symbols {
		var rva uint32
		if sym.SectionNumber > 0 && int(sym.SectionNumber) <= len(peFile.Sections) {
			section := peFile.Sections[sym.SectionNumber-1]
			rva = section.VirtualAddress + sym.Value
		} else {
			continue
		}

		switch sym.Name {
		case "runtime.pclntab":
			pclntabRVA = rva
		case "runtime.epclntab":
			epclntabRVA = rva
		case "runtime.symtab":
			symtabRVA = rva
		case "runtime.esymtab":
			esymtabRVA = rva
		}
	}

	if pclntabRVA == 0 || epclntabRVA == 0 {
		return nil, nil, fmt.Errorf("runtime.pclntab or runtime.epclntab symbols not found")
	}

	// symtabRVA and esymtabRVA may be 0 or equal for modern Go binaries that don't have symtab
	// This is acceptable as gosym.NewTable can work with an empty symtab

	// Helper function to extract data from RVA range
	extractRVARange := func(startRVA, endRVA uint32) ([]byte, error) {
		var result []byte
		currentRVA := startRVA

		for currentRVA < endRVA {
			// Find section containing currentRVA or the next section if we're in a gap
			// We need to check against actual data availability, not just VirtualSize
			var section *pe.Section
			var sectionData []byte
			var nextSectionRVA uint32 = noNextSectionRVA

			for _, s := range peFile.Sections {
				data, err := s.Data()
				if err != nil {
					continue
				}
				// Check if RVA is within the section's data range
				sectionDataEnd := s.VirtualAddress + uint32(len(data))
				if currentRVA >= s.VirtualAddress && currentRVA < sectionDataEnd {
					section = s
					sectionData = data
					break
				}
				// Track the next section after currentRVA for gap handling
				if s.VirtualAddress > currentRVA && s.VirtualAddress < nextSectionRVA {
					nextSectionRVA = s.VirtualAddress
				}
			}

			// If no section found, we might be in a gap between sections
			if section == nil {
				if nextSectionRVA != noNextSectionRVA && nextSectionRVA < endRVA {
					// Skip the gap to the next section
					currentRVA = nextSectionRVA
					continue
				}
				return nil, fmt.Errorf("no section found for RVA 0x%x and no next section available", currentRVA)
			}

			// Calculate how much to copy from this section
			offsetInSection := currentRVA - section.VirtualAddress
			sectionEnd := section.VirtualAddress + uint32(len(sectionData))
			copyEnd := endRVA
			if copyEnd > sectionEnd {
				copyEnd = sectionEnd
			}
			copySize := copyEnd - currentRVA

			// Bounds check
			if offsetInSection >= uint32(len(sectionData)) {
				return nil, fmt.Errorf("offset 0x%x beyond section %s data length 0x%x",
					offsetInSection, section.Name, len(sectionData))
			}

			endOffset := offsetInSection + copySize
			if endOffset > uint32(len(sectionData)) {
				endOffset = uint32(len(sectionData))
				copySize = endOffset - offsetInSection
			}

			// Copy data
			result = append(result, sectionData[offsetInSection:endOffset]...)
			currentRVA += copySize
		}

		return result, nil
	}

	// Extract pclntab and symtab
	pclntab, err = extractRVARange(pclntabRVA, epclntabRVA)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract pclntab: %w", err)
	}

	// Extract symtab if symbols exist and have a valid range
	if symtabRVA != 0 && esymtabRVA != 0 && symtabRVA != esymtabRVA {
		symtab, err = extractRVARange(symtabRVA, esymtabRVA)
		if err != nil {
			// Symtab extraction failure is not fatal for modern Go binaries
			// Return empty symtab instead of failing
			symtab = []byte{}
		}
	} else {
		// No symtab or empty symtab - this is normal for modern Go binaries
		symtab = []byte{}
	}

	return pclntab, symtab, nil
}

func getPackageName(funcName string) string {
	// Function names in Go are typically in the form "package/path.FuncName"
	// or "package/path.(*Type).Method"

	// Strip trailing semicolons and other special characters
	funcName = strings.TrimRight(funcName, ";")

	// Skip type information completely
	if strings.HasPrefix(funcName, "type:") {
		return ""
	}

	// Handle go: special patterns (like go:struct, go:itab, etc.)
	// These contain package information that should be extracted
	if strings.HasPrefix(funcName, "go:") {
		// go:struct { <package> - extract package after "go:struct { "
		if strings.HasPrefix(funcName, "go:struct {") {
			rest := strings.TrimPrefix(funcName, "go:struct {")
			rest = strings.TrimSpace(rest)
			// Extract package name (could be github.com/user/pkg or just pkg)
			parts := strings.Fields(rest)
			if len(parts) > 0 {
				return parts[0]
			}
		}
		
		// go:itab.*pkg.Type,interface - extract package from type
		if strings.HasPrefix(funcName, "go:itab.") {
			rest := strings.TrimPrefix(funcName, "go:itab.")
			// Skip leading * if present
			rest = strings.TrimPrefix(rest, "*")
			// Extract up to comma
			if idx := strings.Index(rest, ","); idx != -1 {
				rest = rest[:idx]
			}
			// Extract package from Type reference (pkg.Type)
			if idx := strings.LastIndex(rest, "."); idx != -1 {
				return rest[:idx]
			}
		}
		
		// For other go: patterns we don't recognize, skip them
		return ""
	}

	// Strip generic instantiation suffixes: anything from [ onwards
	// e.g., "slices.partitionCmpFunc[go.shape" -> "slices.partitionCmpFunc"
	if idx := strings.Index(funcName, "["); idx != -1 {
		funcName = funcName[:idx]
	}

	// Handle method receivers like "pkg.(*Type).Method"
	// First extract the part before (*Type) so we can process it further
	hadMethodReceiver := false
	if strings.Contains(funcName, "(*") {
		// Find the package path before (*Type)
		idx := strings.Index(funcName, ".(")
		if idx != -1 {
			funcName = funcName[:idx]
			hadMethodReceiver = true
			// Continue processing to handle Type.method patterns that might be before the (*Type)
			// e.g., "pkg.type.method.(*Type).Method" should extract "pkg"
		}
	}

	// Handle .init functions specially - they should be attributed to the package
	// MUST be done BEFORE Type.method detection to avoid issues with .init.N.funcM patterns
	// e.g., "github.com/user/pkg.init" or "github.com/user/pkg.init.0.func1"
	if strings.HasSuffix(funcName, ".init") {
		// Remove the .init suffix and return
		pkgName := strings.TrimSuffix(funcName, ".init")
		if decoded, err := url.QueryUnescape(pkgName); err == nil {
			return decoded
		}
		return pkgName
	}
	// Also handle .init.N suffixes (e.g., "github.com/user/pkg.init.0.func1")
	if idx := strings.LastIndex(funcName, ".init."); idx != -1 {
		pkgName := funcName[:idx]
		if decoded, err := url.QueryUnescape(pkgName); err == nil {
			return decoded
		}
		return pkgName
	}

	// Handle type methods like "pkg.Type.Method" or "strings.Builder.grow"
	// We need to extract the package before the type name
	// Split by dots and check if we have Type.Method pattern
	parts := strings.Split(funcName, ".")
	
	// If we just processed a (*Type).Method and have only 2 parts like ["github", "com/user/pkg"],
	// this is already a valid package path, so don't process it further
	if hadMethodReceiver && len(parts) == 2 && strings.Contains(parts[1], "/") {
		// URL decode the package name
		if decoded, err := url.QueryUnescape(funcName); err == nil {
			return decoded
		}
		return funcName
	}
	
	if len(parts) >= 3 {
		// For "strings.Builder.grow", we want "strings"
		// For "github.com/user/pkg.MyType.Method", we want "github.com/user/pkg"
		// For "runtime.traceLocker.Lock", we want "runtime"
		// For "google.golang.org/protobuf/internal/detrand", we want the full path
		
		// Check if ANY part contains "/" to determine if this is a domain-based package
		hasSlash := false
		for _, part := range parts {
			if strings.Contains(part, "/") {
				hasSlash = true
				break
			}
		}
		
		if !hasSlash {
			// For stdlib packages with 3+ parts, assume pkg.type.method pattern
			// and extract just the first part
			firstPart := parts[0]
			pkgName := firstPart
			// URL decode the package name
			if decoded, err := url.QueryUnescape(pkgName); err == nil {
				return decoded
			}
			return pkgName
		}
		
		// For non-stdlib packages with domain paths (e.g., github.com/user/pkg.Type.Method)
		// Check if we have at least 4 parts and the pattern looks like a Type.method
		if len(parts) >= 4 {
			// The second-to-last part should be the Type name
			// Remove both the Type and method to get the package path
			pkgParts := parts[:len(parts)-2]
			pkgName := strings.Join(pkgParts, ".")
			// URL decode the package name
			if decoded, err := url.QueryUnescape(pkgName); err == nil {
				return decoded
			}
			return pkgName
		}
	}

	// Split by last dot to separate package from function/method
	lastDot := strings.LastIndex(funcName, ".")
	if lastDot == -1 {
		return ""
	}

	pkgName := funcName[:lastDot]

	// URL decode the package name
	if decoded, err := url.QueryUnescape(pkgName); err == nil {
		return decoded
	}
	return pkgName
}

func isExternalDependency(pkgName string) bool {
	// Skip only these special compiler-generated patterns
	if strings.HasPrefix(pkgName, "go.shape") ||
		strings.HasPrefix(pkgName, "weak.") ||
		strings.HasPrefix(pkgName, "unique.") {
		return false
	}

	// Include everything else: stdlib, external deps, golang.org/x, type info, etc.
	return pkgName != ""
}

func getModuleName(pkgName string, modulePaths []string) string {
	// Iterate through module dependencies in order (longest first) to find the module
	// that each symbol can be attributed to
	for _, modPath := range modulePaths {
		// Check for exact match or if package is a subpackage of this module
		if pkgName == modPath || strings.HasPrefix(pkgName, modPath+"/") {
			return modPath
		}
	}

	// If no module dependencies match, check if the symbol comes from stdlib
	// Stdlib packages don't have a domain (no path separator, or path doesn't look like a domain)
	parts := strings.Split(pkgName, "/")
	if len(parts) == 0 {
		if *verbose {
			fmt.Fprintf(os.Stderr, "[verbose] Empty package name, attributing to 'other'\n")
		}
		return "other"
	}

	// If not in module dependencies, check if it's a standard library package
	// Stdlib packages don't contain dots in the first path component
	// (e.g., "runtime", "net/http", "encoding/json")
	firstPart := parts[0]
	
	if !strings.Contains(firstPart, ".") {
		// No dot in first component - stdlib package
		return firstPart
	}

	// First component contains a dot
	// If it's a single component (no /), treat as stdlib with suffix and extract base
	// (e.g., "unicode.map" → "unicode")
	// If multiple components, it's a domain-based package not in BuildInfo
	if len(parts) == 1 {
		// Single component with dot - extract base before first dot
		base := strings.Split(firstPart, ".")[0]
		return base
	}

	// Multiple components with dot in first - not in BuildInfo
	if *verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Package %q not in BuildInfo and not stdlib, attributing to 'other'\n", pkgName)
	}
	return "other"
}

func printReport(report *DependencyReport) {
	if len(report.Packages) == 0 {
		fmt.Println("No dependencies found in binary")
		return
	}

	// Sort packages by size (descending)
	type pkgSize struct {
		name string
		size int64
	}

	packages := make([]pkgSize, 0, len(report.Packages))
	for name, size := range report.Packages {
		packages = append(packages, pkgSize{name, size})
	}

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].size > packages[j].size
	})

	fmt.Println("Dependency Size Report")
	fmt.Println("======================")
	fmt.Println()

	for _, pkg := range packages {
		var percentage float64
		if report.TotalSize == 0 {
			percentage = 0
		} else {
			percentage = float64(pkg.size) / float64(report.TotalSize) * 100
		}
		fmt.Printf("%-50s %10s (%5.1f%%)\n",
			truncatePackageName(pkg.name, 50),
			formatSize(pkg.size),
			percentage)
	}

	fmt.Println()
	fmt.Printf("Total size: %s\n", formatSize(report.TotalSize))
}

const (
	truncationSuffix    = "...."
	truncationSuffixLen = len(truncationSuffix)
)

func truncatePackageName(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	if maxLen < truncationSuffixLen {
		return name[:maxLen]
	}
	return name[:maxLen-truncationSuffixLen] + truncationSuffix
}

func formatSize(size int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
	)

	if size >= MB {
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	} else if size >= KB {
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	}
	return fmt.Sprintf("%d B", size)
}
