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

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary>\n", os.Args[0])
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
	TotalSize int64
	Packages  map[string]int64
	Modules   map[string]string // map from package path to module path
}

func analyzeBinary(path string) (*DependencyReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary: %w", err)
	}
	defer f.Close()

	// Extract BuildInfo to get module dependencies
	buildInfo, err := buildinfo.ReadFile(path)
	moduleMap := make(map[string]string)
	if err == nil && buildInfo != nil {
		// Map package paths to their module paths
		for _, dep := range buildInfo.Deps {
			if dep != nil {
				moduleMap[dep.Path] = dep.Path
			}
		}
	}

	// Try all supported binary formats in order
	return tryParsers(f, moduleMap)
}

// tryParsers attempts to analyze the binary using all supported formats in order.
func tryParsers(r io.ReaderAt, moduleMap map[string]string) (*DependencyReport, error) {
	parsers := []func(io.ReaderAt, map[string]string) (*DependencyReport, error){
		analyzeELF,
		analyzeMachO,
		analyzePE,
	}
	for _, parser := range parsers {
		report, err := parser(r, moduleMap)
		if err == nil {
			return report, nil
		}
	}
	return nil, fmt.Errorf("unsupported binary format (not ELF, Mach-O, or PE)")
}

func analyzeELF(r io.ReaderAt, moduleMap map[string]string) (*DependencyReport, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()

	return analyzeSymbols(elfFile, moduleMap)
}

func analyzeMachO(r io.ReaderAt, moduleMap map[string]string) (*DependencyReport, error) {
	machoFile, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer machoFile.Close()

	return analyzeSymbolsMachO(machoFile, moduleMap)
}

func analyzePE(r io.ReaderAt, moduleMap map[string]string) (*DependencyReport, error) {
	peFile, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	return analyzeSymbolsPE(peFile, moduleMap)
}

func analyzeSymbols(elfFile *elf.File, moduleMap map[string]string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages: make(map[string]int64),
		Modules:  moduleMap,
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
	processSymbolTable(table, moduleMap, report)

	return report, nil
}

func analyzeLineTable(pcln *gosym.LineTable, report *DependencyReport) (*DependencyReport, error) {
	// For newer Go versions without .gosymtab, we cannot perform detailed analysis
	// as we lack the function symbol information needed to attribute sizes
	return nil, fmt.Errorf("analysis not supported for binaries without .gosymtab (Go symbol table)")
}

// processSymbolTable analyzes function symbols and attributes their sizes to modules
func processSymbolTable(table *gosym.Table, moduleMap map[string]string, report *DependencyReport) {
	for _, fn := range table.Funcs {
		pkgName := getPackageName(fn.Name)
		if pkgName != "" && isExternalDependency(pkgName) {
			moduleName := getModuleName(pkgName, moduleMap)
			report.Packages[moduleName] += int64(fn.End - fn.Entry)
			report.TotalSize += int64(fn.End - fn.Entry)
		}
	}
}

func analyzeSymbolsMachO(machoFile *macho.File, moduleMap map[string]string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages: make(map[string]int64),
		Modules:  moduleMap,
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
		processSymbolTable(table, moduleMap, report)
	}

	return report, nil
}

func analyzeSymbolsPE(peFile *pe.File, moduleMap map[string]string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages: make(map[string]int64),
		Modules:  moduleMap,
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

	processSymbolTable(table, moduleMap, report)
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
	if strings.Contains(funcName, "(*") {
		// Find the package path before (*Type)
		idx := strings.Index(funcName, ".(")
		if idx != -1 {
			pkgName := funcName[:idx]
			// URL decode the package name
			if decoded, err := url.QueryUnescape(pkgName); err == nil {
				return decoded
			}
			return pkgName
		}
	}

	// Handle type methods like "pkg.Type.Method" or "strings.Builder.grow"
	// We need to extract the package before the type name
	// Split by dots and check if we have Type.Method pattern
	parts := strings.Split(funcName, ".")
	if len(parts) >= 3 {
		// For "strings.Builder.grow", we want "strings"
		// For "github.com/user/pkg.MyType.Method", we want "github.com/user/pkg"
		// For "runtime.traceLocker.Lock", we want "runtime"
		
		// Check if this looks like a stdlib package (first component has no slash)
		// AND the full package path has no slashes
		firstPart := parts[0]
		fullPkgBeforeLastDot := strings.Join(parts[:len(parts)-1], ".")
		if !strings.Contains(firstPart, "/") && !strings.Contains(fullPkgBeforeLastDot, "/") {
			// For stdlib packages with 3+ parts, assume pkg.type.method pattern
			// and extract just the first part
			pkgName := firstPart
			// URL decode the package name
			if decoded, err := url.QueryUnescape(pkgName); err == nil {
				return decoded
			}
			return pkgName
		}
		
		// For non-stdlib packages, check if the second-to-last part looks like a Type (starts with uppercase)
		secondToLast := parts[len(parts)-2]
		if len(secondToLast) > 0 && (secondToLast[0] >= 'A' && secondToLast[0] <= 'Z') {
			// This might be a Type.method pattern
			// Remove the last part (method) and the second-to-last part (Type)
			pkgParts := parts[:len(parts)-2]
			if len(pkgParts) > 0 {
				pkgName := strings.Join(pkgParts, ".")
				// URL decode the package name
				if decoded, err := url.QueryUnescape(pkgName); err == nil {
					return decoded
				}
				return pkgName
			}
		}
	}

	// Split by last dot to separate package from function/method
	lastDot := strings.LastIndex(funcName, ".")
	if lastDot == -1 {
		return ""
	}

	pkgName := funcName[:lastDot]

	// Remove .init suffix if present (e.g., "github.com/user/pkg.init" -> "github.com/user/pkg")
	if strings.HasSuffix(pkgName, ".init") {
		pkgName = strings.TrimSuffix(pkgName, ".init")
	}
	// Also handle .init.N suffixes (e.g., "github.com/user/pkg.init.0")
	if idx := strings.LastIndex(pkgName, ".init."); idx != -1 {
		pkgName = pkgName[:idx]
	}

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

func getModuleName(pkgName string, moduleMap map[string]string) string {
	// First, try to find an exact match in the module map
	if modulePath, ok := moduleMap[pkgName]; ok {
		return modulePath
	}

	// Try to find the longest prefix match in the module map
	longestMatch := ""
	for modPath := range moduleMap {
		if strings.HasPrefix(pkgName, modPath+"/") && len(modPath) > len(longestMatch) {
			longestMatch = modPath
		}
	}
	if longestMatch != "" {
		return longestMatch
	}

	// Fallback to heuristic approach for packages not in module map
	// For standard library packages (no dots in first component), keep only first path component
	// For external modules (domain-like), keep first 3 components for typical github.com/user/repo pattern

	parts := strings.Split(pkgName, "/")
	if len(parts) == 0 {
		return pkgName
	}

	firstPart := parts[0]

	// Check if it's a domain-based module (contains a dot)
	if strings.Contains(firstPart, ".") {
		// For github.com/user/repo/..., golang.org/x/package/..., etc.
		// Keep first 3 parts: github.com/user/repo or golang.org/x/package
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
		return pkgName
	}

	// For stdlib or simple packages, return just the first component
	return firstPart
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
