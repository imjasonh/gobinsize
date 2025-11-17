package main

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	svg "github.com/ajstarks/svgo"
	"golang.org/x/tools/go/packages"
)

var (
	verbose = flag.Bool("verbose", false, "enable verbose logging for debugging attribution")
	svgFile = flag.String("svg", "", "output SVG treemap to the specified file")
)

var (
	stdlibPackages     []string
	stdlibPackagesOnce sync.Once
)

// getStdlibPackages returns the list of standard library packages
// Source - https://stackoverflow.com/a/53541580
// Posted by Martin Tournoij, modified by community. See post 'Timeline' for change history
// Retrieved 2025-11-17, License - CC BY-SA 4.0
func getStdlibPackages() []string {
	stdlibPackagesOnce.Do(func() {
		pkgs, err := packages.Load(nil, "std")
		if err != nil {
			// Fallback to empty list if loading fails
			fmt.Fprintf(os.Stderr, "Warning: failed to get stdlib packages: %v\n", err)
			stdlibPackages = []string{}
			return
		}

		stdlibPackages = make([]string, 0, len(pkgs))
		for _, pkg := range pkgs {
			if pkg.PkgPath != "" && pkg.PkgPath != "main" {
				stdlibPackages = append(stdlibPackages, pkg.PkgPath)
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
		fmt.Fprintf(os.Stderr, "Usage: %s [-verbose] [-svg output.svg] <binary>\n", os.Args[0])
		os.Exit(1)
	}

	binaryPath := flag.Arg(0)

	report, err := analyzeBinary(binaryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing binary: %v\n", err)
		os.Exit(1)
	}

	printReport(report)

	// Generate SVG treemap if requested
	if *svgFile != "" {
		if err := generateSVGTreemap(report, *svgFile, binaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating SVG: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SVG treemap written to %s\n", *svgFile)
	}
}

type DependencyReport struct {
	TotalSize    int64
	TotalCode    int64
	TotalData    int64
	TotalDebug   int64
	TotalSymbols int64
	Packages     map[string]*PackageSize
	ModulePaths  []string // sorted list of module paths (longest first)
}

type PackageSize struct {
	Code    int64
	Data    int64
	Debug   int64
	Symbols int64
}

type pkgSize struct {
	name string
	size int64
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
		Packages:    make(map[string]*PackageSize),
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

	// Analyze data symbols from ELF symbol table
	analyzeELFDataSymbols(elfFile, modulePaths, report)

	// Analyze debug info
	analyzeDWARF(elfFile, modulePaths, report)

	// Analyze symbol tables
	analyzeSymbolTables(elfFile, modulePaths, report)

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
			size := int64(fn.End - fn.Entry)
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Code += size
			report.TotalCode += size
			report.TotalSize += size
		}
	}
}

// analyzeELFDataSymbols analyzes data symbols from the ELF symbol table
func analyzeELFDataSymbols(elfFile *elf.File, modulePaths []string, report *DependencyReport) {
	symbols, err := elfFile.Symbols()
	if err != nil {
		// Symbols may not be available in stripped binaries
		return
	}

	// Sort symbols by address to calculate sizes
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Value < symbols[j].Value
	})

	// Get data section boundaries
	dataSections := make(map[string]*elf.Section)
	for _, name := range []string{".rodata", ".data", ".bss", ".noptrdata", ".typelink"} {
		if sec := elfFile.Section(name); sec != nil {
			dataSections[name] = sec
		}
	}

	for i := 0; i < len(symbols); i++ {
		sym := symbols[i]

		// Check if this is a data symbol (in data sections)
		isData := false
		for _, sec := range dataSections {
			if sym.Value >= sec.Addr && sym.Value < sec.Addr+sec.Size {
				isData = true
				break
			}
		}

		if !isData {
			continue
		}

		// Calculate symbol size
		var size uint64
		if i+1 < len(symbols) && symbols[i+1].Value > sym.Value {
			// Use next symbol's address to calculate size
			size = symbols[i+1].Value - sym.Value
		} else {
			// Last symbol or no next symbol - use a default small size
			size = 8
		}

		// Attribute to module
		moduleName := findModuleForSymbol(sym.Name, modulePaths)
		if moduleName != "" && moduleName != "main" {
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Data += int64(size)
			report.TotalData += int64(size)
			report.TotalSize += int64(size)
		}
	}
}

func analyzeSymbolsMachO(machoFile *macho.File, modulePaths []string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages:    make(map[string]*PackageSize),
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

	// Analyze data symbols from Mach-O symbol table
	analyzeMachODataSymbols(machoFile, modulePaths, report)

	// Analyze debug info
	analyzeDWARF(machoFile, modulePaths, report)

	// Analyze symbol tables
	analyzeSymbolTables(machoFile, modulePaths, report)

	return report, nil
}

// analyzeMachODataSymbols analyzes data symbols from the Mach-O symbol table
func analyzeMachODataSymbols(machoFile *macho.File, modulePaths []string, report *DependencyReport) {
	if machoFile.Symtab == nil {
		return
	}

	// Sort symbols by address to calculate sizes
	syms := machoFile.Symtab.Syms
	sort.Slice(syms, func(i, j int) bool {
		return syms[i].Value < syms[j].Value
	})

	// Get data section boundaries
	dataSections := make(map[string]*macho.Section)
	for _, name := range []string{"__rodata", "__data", "__bss", "__noptrdata", "__typelink", "__const", "__go_buildinfo"} {
		for _, sec := range machoFile.Sections {
			if sec.Name == name {
				dataSections[name] = sec
				break
			}
		}
	}

	for i := 0; i < len(syms); i++ {
		sym := syms[i]

		// Check if this is a data symbol (in data sections)
		isData := false
		for _, sec := range dataSections {
			if sym.Value >= sec.Addr && sym.Value < sec.Addr+sec.Size {
				isData = true
				break
			}
		}

		if !isData {
			continue
		}

		// Calculate symbol size
		var size uint64
		if i+1 < len(syms) && syms[i+1].Value > sym.Value {
			// Use next symbol's address to calculate size
			size = syms[i+1].Value - sym.Value
		} else {
			// Last symbol or no next symbol - use a default small size
			size = 8
		}

		// Attribute to module
		moduleName := findModuleForSymbol(sym.Name, modulePaths)
		if moduleName != "" && moduleName != "main" {
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Data += int64(size)
			report.TotalData += int64(size)
			report.TotalSize += int64(size)
		}
	}
}

func analyzeSymbolsPE(peFile *pe.File, modulePaths []string) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages:    make(map[string]*PackageSize),
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

	// Analyze data symbols from PE symbol table
	analyzePEDataSymbols(peFile, modulePaths, report)

	// Analyze debug info
	analyzeDWARF(peFile, modulePaths, report)

	// Analyze symbol tables
	analyzeSymbolTables(peFile, modulePaths, report)

	return report, nil
}

// analyzePEDataSymbols analyzes data symbols from the PE symbol table
func analyzePEDataSymbols(peFile *pe.File, modulePaths []string, report *DependencyReport) {
	if peFile.Symbols == nil || len(peFile.Symbols) == 0 {
		return
	}

	// Sort symbols by section and value to calculate sizes
	symbols := make([]*pe.Symbol, len(peFile.Symbols))
	copy(symbols, peFile.Symbols)
	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].SectionNumber != symbols[j].SectionNumber {
			return symbols[i].SectionNumber < symbols[j].SectionNumber
		}
		return symbols[i].Value < symbols[j].Value
	})

	// Identify data sections
	dataSectionNames := map[string]bool{
		".rdata": true, ".data": true, ".bss": true,
	}

	for i := 0; i < len(symbols); i++ {
		sym := symbols[i]

		// Skip invalid section numbers
		if sym.SectionNumber < 1 || int(sym.SectionNumber) > len(peFile.Sections) {
			continue
		}

		section := peFile.Sections[sym.SectionNumber-1]

		// Check if this is a data section
		if !dataSectionNames[section.Name] {
			continue
		}

		// Calculate symbol size
		var size uint32
		if i+1 < len(symbols) && symbols[i+1].SectionNumber == sym.SectionNumber && symbols[i+1].Value > sym.Value {
			// Use next symbol's address to calculate size
			size = symbols[i+1].Value - sym.Value
		} else {
			// Last symbol or no next symbol - use a default small size
			size = 8
		}

		// Attribute to module
		moduleName := findModuleForSymbol(sym.Name, modulePaths)
		if moduleName != "" && moduleName != "main" {
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Data += int64(size)
			report.TotalData += int64(size)
			report.TotalSize += int64(size)
		}
	}
}

// dwarfReader is an interface for types that can provide DWARF data
type dwarfReader interface {
	DWARF() (*dwarf.Data, error)
}

// analyzeDWARF analyzes debug info and attributes it to modules based on compile units
func analyzeDWARF(file dwarfReader, modulePaths []string, report *DependencyReport) {
	dwarfData, err := file.DWARF()
	if err != nil {
		// No DWARF data or error reading it - this is okay
		return
	}

	// Get total debug section sizes by type of file
	var debugSectionSizes map[string]uint64
	switch f := file.(type) {
	case *elf.File:
		debugSectionSizes = getELFDebugSectionSizes(f)
	case *macho.File:
		debugSectionSizes = getMachODebugSectionSizes(f)
	case *pe.File:
		debugSectionSizes = getPEDebugSectionSizes(f)
	}

	var totalDebugSize uint64
	for _, size := range debugSectionSizes {
		totalDebugSize += size
	}

	if totalDebugSize == 0 {
		return
	}

	// Count compile units per package to calculate proportional sizes
	packageCUCounts := make(map[string]int)
	totalCUs := 0

	reader := dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			totalCUs++
			// Get the package name from the compile unit
			nameVal := entry.Val(dwarf.AttrName)
			if nameVal == nil {
				continue
			}

			packageName, ok := nameVal.(string)
			if !ok {
				continue
			}

			// Find which module this package belongs to
			moduleName := findModuleForSymbol(packageName, modulePaths)
			if moduleName != "" && moduleName != "main" {
				packageCUCounts[moduleName]++
			}
		}
	}

	// Distribute debug info size proportionally based on compile unit count
	if totalCUs > 0 {
		for moduleName, cuCount := range packageCUCounts {
			// Calculate proportional debug size for this module
			debugSize := int64(float64(totalDebugSize) * float64(cuCount) / float64(totalCUs))

			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Debug += debugSize
			report.TotalDebug += debugSize
			report.TotalSize += debugSize
		}
	}
}

// getELFDebugSectionSizes returns the sizes of debug sections in an ELF file
func getELFDebugSectionSizes(f *elf.File) map[string]uint64 {
	sizes := make(map[string]uint64)
	debugSectionPrefixes := []string{".debug_", ".zdebug_"}

	for _, section := range f.Sections {
		for _, prefix := range debugSectionPrefixes {
			if strings.HasPrefix(section.Name, prefix) {
				sizes[section.Name] = section.Size
				break
			}
		}
	}
	return sizes
}

// getMachODebugSectionSizes returns the sizes of debug sections in a Mach-O file
func getMachODebugSectionSizes(f *macho.File) map[string]uint64 {
	sizes := make(map[string]uint64)
	debugSectionPrefixes := []string{"__debug_", "__zdebug_"}

	for _, section := range f.Sections {
		for _, prefix := range debugSectionPrefixes {
			if strings.HasPrefix(section.Name, prefix) {
				sizes[section.Name] = section.Size
				break
			}
		}
	}
	return sizes
}

// getPEDebugSectionSizes returns the sizes of debug sections in a PE file
func getPEDebugSectionSizes(f *pe.File) map[string]uint64 {
	sizes := make(map[string]uint64)
	debugSectionPrefixes := []string{".debug_", ".zdebug_"}

	for _, section := range f.Sections {
		for _, prefix := range debugSectionPrefixes {
			if strings.HasPrefix(section.Name, prefix) {
				sizes[section.Name] = uint64(section.Size)
				break
			}
		}
	}
	return sizes
}

// symbolTableReader is an interface for types that can provide symbol table info
type symbolTableReader interface{}

// analyzeSymbolTables analyzes symbol table sections and attributes them to modules
func analyzeSymbolTables(file interface{}, modulePaths []string, report *DependencyReport) {
	switch f := file.(type) {
	case *elf.File:
		analyzeELFSymbolTables(f, modulePaths, report)
	case *macho.File:
		analyzeMachOSymbolTables(f, modulePaths, report)
	case *pe.File:
		analyzePESymbolTables(f, modulePaths, report)
	}
}

// analyzeELFSymbolTables analyzes symbol table sections in ELF files
func analyzeELFSymbolTables(f *elf.File, modulePaths []string, report *DependencyReport) {
	// Get symbol table related sections
	symtabSections := []string{".symtab", ".strtab", ".gosymtab", ".gopclntab"}

	// Count symbols per package
	packageSymbolCounts := make(map[string]int)
	totalSymbols := 0

	symbols, err := f.Symbols()
	if err == nil {
		for _, sym := range symbols {
			moduleName := findModuleForSymbol(sym.Name, modulePaths)
			if moduleName != "" && moduleName != "main" {
				packageSymbolCounts[moduleName]++
				totalSymbols++
			}
		}
	}

	// Get total size of symbol table sections
	var totalSymbolTableSize uint64
	for _, secName := range symtabSections {
		if sec := f.Section(secName); sec != nil {
			totalSymbolTableSize += sec.Size
		}
	}

	// Distribute proportionally
	if totalSymbols > 0 && totalSymbolTableSize > 0 {
		for moduleName, count := range packageSymbolCounts {
			symbolSize := int64(float64(totalSymbolTableSize) * float64(count) / float64(totalSymbols))
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Symbols += symbolSize
			report.TotalSymbols += symbolSize
			report.TotalSize += symbolSize
		}
	}
}

// analyzeMachOSymbolTables analyzes symbol table sections in Mach-O files
func analyzeMachOSymbolTables(f *macho.File, modulePaths []string, report *DependencyReport) {
	// Get symbol table related sections
	symtabSections := []string{"__gosymtab", "__gopclntab", "__symbol_stub1"}

	// Count symbols per package using Go symbol table
	packageSymbolCounts := make(map[string]int)
	totalSymbols := 0

	// Try to get Go function symbols from gosym table
	var pclntabData []byte
	var textAddr uint64
	for _, section := range f.Sections {
		if section.Name == "__gopclntab" {
			data, err := section.Data()
			if err == nil {
				pclntabData = data
			}
		}
		if section.Name == "__text" {
			textAddr = section.Addr
		}
	}

	if pclntabData != nil {
		var symtabData []byte
		for _, section := range f.Sections {
			if section.Name == "__gosymtab" {
				data, err := section.Data()
				if err == nil {
					symtabData = data
				}
				break
			}
		}

		pcln := gosym.NewLineTable(pclntabData, textAddr)
		table, err := gosym.NewTable(symtabData, pcln)
		if err == nil && len(table.Funcs) > 0 {
			// Use Go functions from gosym table
			for _, fn := range table.Funcs {
				moduleName := findModuleForSymbol(fn.Name, modulePaths)
				if moduleName != "" && moduleName != "main" {
					packageSymbolCounts[moduleName]++
					totalSymbols++
				}
			}
		} else if f.Symtab != nil {
			// Fallback to Mach-O symtab if gosym fails
			for _, sym := range f.Symtab.Syms {
				moduleName := findModuleForSymbol(sym.Name, modulePaths)
				if moduleName != "" && moduleName != "main" {
					packageSymbolCounts[moduleName]++
					totalSymbols++
				}
			}
		}
	}

	// Get total size of symbol table sections
	var totalSymbolTableSize uint64
	for _, sec := range f.Sections {
		for _, secName := range symtabSections {
			if sec.Name == secName {
				totalSymbolTableSize += sec.Size
				break
			}
		}
	}

	// The Mach-O symtab command also has size info
	// We need to account for the actual symbol table data stored in the file
	if f.Symtab != nil {
		// Approximate: each symbol ~16 bytes + string table
		totalSymbolTableSize += uint64(len(f.Symtab.Syms) * 16)
	}

	// Distribute proportionally
	if totalSymbols > 0 && totalSymbolTableSize > 0 {
		for moduleName, count := range packageSymbolCounts {
			symbolSize := int64(float64(totalSymbolTableSize) * float64(count) / float64(totalSymbols))
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Symbols += symbolSize
			report.TotalSymbols += symbolSize
			report.TotalSize += symbolSize
		}
	}
}

// analyzePESymbolTables analyzes symbol table sections in PE files
func analyzePESymbolTables(f *pe.File, modulePaths []string, report *DependencyReport) {
	// Count symbols per package
	packageSymbolCounts := make(map[string]int)
	totalSymbols := 0

	if f.Symbols != nil {
		for _, sym := range f.Symbols {
			moduleName := findModuleForSymbol(sym.Name, modulePaths)
			if moduleName != "" && moduleName != "main" {
				packageSymbolCounts[moduleName]++
				totalSymbols++
			}
		}
	}

	// Get gopclntab and gosymtab sections
	var totalSymbolTableSize uint64
	for _, sec := range f.Sections {
		if sec.Name == ".gopclntab" || sec.Name == "gopclntab" ||
			sec.Name == ".gosymtab" || sec.Name == "gosymtab" {
			totalSymbolTableSize += uint64(sec.Size)
		}
	}

	// Add approximate symbol table size
	if f.Symbols != nil {
		totalSymbolTableSize += uint64(len(f.Symbols) * 18) // PE COFF symbol size
	}

	// Distribute proportionally
	if totalSymbols > 0 && totalSymbolTableSize > 0 {
		for moduleName, count := range packageSymbolCounts {
			symbolSize := int64(float64(totalSymbolTableSize) * float64(count) / float64(totalSymbols))
			if report.Packages[moduleName] == nil {
				report.Packages[moduleName] = &PackageSize{}
			}
			report.Packages[moduleName].Symbols += symbolSize
			report.TotalSymbols += symbolSize
			report.TotalSize += symbolSize
		}
	}
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

	// Check for internal runtime packages (not in stdlib)
	if strings.HasPrefix(symbolName, "internal/") {
		return "internal"
	}

	// Check for runtime-related symbols without package prefix
	// These are typically assembly functions or compiler-generated code
	if symbolName == "go:buildid" ||
		!strings.Contains(symbolName, ".") && !strings.Contains(symbolName, "/") {
		// Low-level runtime functions, assembly stubs, etc.
		return "runtime"
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

	// Sort packages by total size (descending)
	packages := make([]pkgSize, 0, len(report.Packages))
	for name, ps := range report.Packages {
		totalSize := ps.Code + ps.Data + ps.Debug + ps.Symbols
		packages = append(packages, pkgSize{name, totalSize})
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

		pkgData := report.Packages[pkg.name]
		fmt.Printf("%-40s %10s (%5.1f%%)  [code: %8s, data: %8s, debug: %8s, syms: %8s]\n",
			truncatePackageName(pkg.name, 40),
			formatSize(pkg.size),
			percentage,
			formatSize(pkgData.Code),
			formatSize(pkgData.Data),
			formatSize(pkgData.Debug),
			formatSize(pkgData.Symbols))
	}

	fmt.Println()
	fmt.Printf("Total size: %s  [code: %s, data: %s, debug: %s, syms: %s]\n",
		formatSize(report.TotalSize),
		formatSize(report.TotalCode),
		formatSize(report.TotalData),
		formatSize(report.TotalDebug),
		formatSize(report.TotalSymbols))
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

// generateSVGTreemap creates a treemap visualization of the dependency report
func generateSVGTreemap(report *DependencyReport, filename string, binaryPath string) error {
	if len(report.Packages) == 0 {
		return fmt.Errorf("no dependencies to visualize")
	}

	// Create output file
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	// Sort packages by size (descending)
	packages := make([]pkgSize, 0, len(report.Packages))
	for name, ps := range report.Packages {
		totalSize := ps.Code + ps.Data + ps.Debug + ps.Symbols
		packages = append(packages, pkgSize{name, totalSize})
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].size > packages[j].size
	})

	// Create SVG canvas
	const width, height = 1200, 800
	canvas := svg.New(f)
	canvas.Start(width, height)

	// Title with binary name and total size
	canvas.Rect(0, 0, width, height, "fill:white")
	title := fmt.Sprintf("%s - %s", binaryPath, formatSize(report.TotalSize))
	canvas.Text(width/2, 30, title, "text-anchor:middle;font-size:24px;font-family:Arial,sans-serif;font-weight:bold")

	// Draw treemap
	const margin = 10
	const titleHeight = 50
	treeRect := rect{
		x:      margin,
		y:      titleHeight,
		width:  width - 2*margin,
		height: height - titleHeight - margin,
	}

	drawTreemap(canvas, packages, treeRect)

	canvas.End()
	return nil
}

type rect struct {
	x, y, width, height int
}

// drawTreemap recursively draws a treemap layout
func drawTreemap(canvas *svg.SVG, packages []pkgSize, area rect) {
	if len(packages) == 0 || area.width <= 0 || area.height <= 0 {
		return
	}

	// Calculate total size
	var total int64
	for _, pkg := range packages {
		total += pkg.size
	}

	if total == 0 {
		return
	}

	// Draw each package as a rectangle
	if len(packages) == 1 {
		drawPackageRect(canvas, packages[0], area)
		return
	}

	// Squarified treemap algorithm - split packages based on aspect ratio
	split := findBestSplit(packages, area)

	if split == 0 || split >= len(packages) {
		// Can't split, just draw single package
		drawPackageRect(canvas, packages[0], area)
		return
	}

	// Calculate sizes for split
	var firstGroupSize int64
	for i := 0; i < split; i++ {
		firstGroupSize += packages[i].size
	}

	ratio := float64(firstGroupSize) / float64(total)

	// Determine split direction based on aspect ratio
	if area.width >= area.height {
		// Split vertically
		splitWidth := int(float64(area.width) * ratio)
		if splitWidth < 1 {
			splitWidth = 1
		}
		if splitWidth >= area.width {
			splitWidth = area.width - 1
		}

		leftRect := rect{area.x, area.y, splitWidth, area.height}
		rightRect := rect{area.x + splitWidth, area.y, area.width - splitWidth, area.height}

		drawTreemap(canvas, packages[:split], leftRect)
		drawTreemap(canvas, packages[split:], rightRect)
	} else {
		// Split horizontally
		splitHeight := int(float64(area.height) * ratio)
		if splitHeight < 1 {
			splitHeight = 1
		}
		if splitHeight >= area.height {
			splitHeight = area.height - 1
		}

		topRect := rect{area.x, area.y, area.width, splitHeight}
		bottomRect := rect{area.x, area.y + splitHeight, area.width, area.height - splitHeight}

		drawTreemap(canvas, packages[:split], topRect)
		drawTreemap(canvas, packages[split:], bottomRect)
	}
}

// findBestSplit finds the best split point for squarified treemap
func findBestSplit(packages []pkgSize, area rect) int {
	if len(packages) <= 1 {
		return 0
	}

	// Simple heuristic: split at halfway point by count for now
	// A more sophisticated algorithm would minimize aspect ratios
	return (len(packages) + 1) / 2
}

// drawPackageRect draws a single package rectangle with color and label
func drawPackageRect(canvas *svg.SVG, pkg pkgSize, area rect) {
	if area.width <= 2 || area.height <= 2 {
		return // Too small to draw
	}

	// Generate color based on package name hash
	color := packageColor(pkg.name)

	// Start a group for this package (allows tooltip to work on entire rect)
	canvas.Group("")

	// Add tooltip with full package name and size
	canvas.Title(fmt.Sprintf("%s - %s", pkg.name, formatSize(pkg.size)))

	// Draw rectangle with border
	canvas.Rect(area.x, area.y, area.width, area.height,
		fmt.Sprintf("fill:%s;stroke:white;stroke-width:2", color))

	// Add text label if there's enough space
	const minWidthForText = 50
	const minHeightForText = 25

	if area.width >= minWidthForText && area.height >= minHeightForText {
		centerX := area.x + area.width/2
		centerY := area.y + area.height/2

		// Package name
		fontSize := 12
		if area.height < 40 {
			fontSize = 10
		}

		// Truncate long names
		displayName := pkg.name
		maxNameLen := (area.width - 10) / (fontSize / 2)
		if len(displayName) > maxNameLen && maxNameLen > 3 {
			displayName = displayName[:maxNameLen-3] + "..."
		}

		canvas.Text(centerX, centerY-5, displayName,
			fmt.Sprintf("text-anchor:middle;font-size:%dpx;font-family:Arial,sans-serif;fill:white", fontSize))

		// Size
		if area.height >= 45 {
			canvas.Text(centerX, centerY+10, formatSize(pkg.size),
				fmt.Sprintf("text-anchor:middle;font-size:%dpx;font-family:Arial,sans-serif;fill:white;opacity:0.9", fontSize-2))
		}
	}

	// End the group
	canvas.Gend()
}

// isStdlibPackage checks if a package name is a standard library package
func isStdlibPackage(name string) bool {
	// Check if the package is in the stdlib list
	for _, stdPkg := range getStdlibPackages() {
		if name == stdPkg {
			return true
		}
	}
	return false
}

// packageColor generates a color for a package based on its name
func packageColor(name string) string {
	// Use a light gray for stdlib packages, golang.org/x/..., internal packages, and other
	if isStdlibPackage(name) || strings.HasPrefix(name, "golang.org/x/") || strings.HasPrefix(name, "internal/") || name == "internal" || name == "other" {
		return "#bdc3c7" // light gray
	}

	// Color scheme for non-stdlib packages - use different hues for variety
	colors := []string{
		"#e74c3c", // red
		"#3498db", // blue
		"#2ecc71", // green
		"#f39c12", // orange
		"#9b59b6", // purple
		"#1abc9c", // turquoise
		"#e67e22", // carrot
		"#34495e", // dark blue-grey
		"#16a085", // green sea
		"#c0392b", // darker red
		"#8e44ad", // wisteria
		"#2980b9", // belize blue
		"#27ae60", // nephritis
		"#f1c40f", // sun flower
		"#d35400", // pumpkin
	}

	// Hash the package name to pick a color
	hash := 0
	for _, c := range name {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}

	return colors[hash%len(colors)]
}
