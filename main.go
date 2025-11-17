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
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

var verbose = flag.Bool("verbose", false, "enable verbose logging for debugging attribution")

var (
	stdlibPackages     []string
	stdlibPackagesOnce sync.Once
)

// getStdlibPackages returns the list of standard library packages
func getStdlibPackages() []string {
	stdlibPackagesOnce.Do(func() {
		cmd := exec.Command("go", "list", "std")
		output, err := cmd.Output()
		if err != nil {
			// Fallback to empty list if go list fails
			fmt.Fprintf(os.Stderr, "Warning: failed to get stdlib packages: %v\n", err)
			stdlibPackages = []string{}
			return
		}
		
		// Parse the output - one package per line
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		stdlibPackages = make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && line != "main" {
				stdlibPackages = append(stdlibPackages, line)
			}
		}
		
		// Sort by length (longest first) for better matching
		sort.Slice(stdlibPackages, func(i, j int) bool {
			return len(stdlibPackages[i]) > len(stdlibPackages[j])
		})
	})
	return stdlibPackages
}

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
		// Find which module/package this symbol belongs to
		moduleName := findModuleForSymbol(fn.Name, modulePaths)
		if moduleName != "" && moduleName != "main" {
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

// findModuleForSymbol finds which module or stdlib package a symbol belongs to
// by checking if any module path or stdlib package is contained in the symbol name
func findModuleForSymbol(symbolName string, modulePaths []string) string {
	// Skip compiler-generated symbols
	if strings.HasPrefix(symbolName, "type:") || strings.HasPrefix(symbolName, "go.") {
		return ""
	}
	
	// Check BuildInfo modules first (longest match wins due to pre-sorted order)
	for _, modPath := range modulePaths {
		if strings.Contains(symbolName, modPath) {
			return modPath
		}
	}
	
	// Check stdlib packages (sorted by length, longest first)
	// Stdlib packages can include slashes (e.g., encoding/json)
	for _, stdPkg := range getStdlibPackages() {
		// Check if the symbol starts with the package name followed by .
		if strings.HasPrefix(symbolName, stdPkg+".") {
			return stdPkg
		}
	}
	
	// Check for "main" package
	if strings.HasPrefix(symbolName, "main.") {
		return "main"
	}
	
	// Not recognized - group as "other"
	if *verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Symbol %q not attributed to any module, grouping as 'other'\n", symbolName)
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
