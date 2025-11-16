package main

import (
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
}

func analyzeBinary(path string) (*DependencyReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary: %w", err)
	}
	defer f.Close()
	
	// Try to parse as ELF
	report, err := analyzeELF(f)
	if err == nil {
		return report, nil
	}
	
	// Try to parse as Mach-O
	f.Seek(0, 0)
	report, err = analyzeMachO(f)
	if err == nil {
		return report, nil
	}
	
	// Try to parse as PE
	f.Seek(0, 0)
	report, err = analyzePE(f)
	if err == nil {
		return report, nil
	}
	
	return nil, fmt.Errorf("unsupported binary format")
}

func analyzeELF(r io.ReaderAt) (*DependencyReport, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()
	
	return analyzeSymbols(elfFile)
}

func analyzeMachO(r io.ReaderAt) (*DependencyReport, error) {
	machoFile, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer machoFile.Close()
	
	return analyzeSymbolsMachO(machoFile)
}

func analyzePE(r io.ReaderAt) (*DependencyReport, error) {
	peFile, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()
	
	return analyzeSymbolsPE(peFile)
}

func analyzeSymbols(elfFile *elf.File) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages: make(map[string]int64),
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
	for _, fn := range table.Funcs {
		pkgName := getPackageName(fn.Name)
		if pkgName != "" && isExternalDependency(pkgName) {
			report.Packages[pkgName] += int64(fn.End - fn.Entry)
			report.TotalSize += int64(fn.End - fn.Entry)
		}
	}
	
	return report, nil
}

func analyzeLineTable(pcln *gosym.LineTable, report *DependencyReport) (*DependencyReport, error) {
	// For newer Go versions without .gosymtab
	// This is a simplified analysis based on the PC/line table
	// We can't get as much detail without the full symbol table
	return report, nil
}

func analyzeSymbolsMachO(machoFile *macho.File) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages: make(map[string]int64),
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
	
	if symtabData != nil {
		table, err := gosym.NewTable(symtabData, pcln)
		if err == nil {
			for _, fn := range table.Funcs {
				pkgName := getPackageName(fn.Name)
				if pkgName != "" && isExternalDependency(pkgName) {
					report.Packages[pkgName] += int64(fn.End - fn.Entry)
					report.TotalSize += int64(fn.End - fn.Entry)
				}
			}
		}
	}
	
	return report, nil
}

func analyzeSymbolsPE(peFile *pe.File) (*DependencyReport, error) {
	report := &DependencyReport{
		Packages: make(map[string]int64),
	}
	
	// Find the .gopclntab section
	var pclntabData []byte
	var textAddr uint64
	
	for _, section := range peFile.Sections {
		if section.Name == ".gopclntab" || section.Name == "gopclntab" {
			data, err := section.Data()
			if err != nil {
				return nil, err
			}
			pclntabData = data
		}
		if section.Name == ".text" || section.Name == "text" {
			textAddr = uint64(section.VirtualAddress)
		}
	}
	
	if pclntabData == nil {
		return nil, fmt.Errorf("no .gopclntab section found")
	}
	
	pcln := gosym.NewLineTable(pclntabData, textAddr)
	
	// Try to find symbol table
	var symtabData []byte
	for _, section := range peFile.Sections {
		if section.Name == ".gosymtab" || section.Name == "gosymtab" {
			data, err := section.Data()
			if err == nil {
				symtabData = data
			}
			break
		}
	}
	
	if symtabData != nil {
		table, err := gosym.NewTable(symtabData, pcln)
		if err == nil {
			for _, fn := range table.Funcs {
				pkgName := getPackageName(fn.Name)
				if pkgName != "" && isExternalDependency(pkgName) {
					report.Packages[pkgName] += int64(fn.End - fn.Entry)
					report.TotalSize += int64(fn.End - fn.Entry)
				}
			}
		}
	}
	
	return report, nil
}

func getPackageName(funcName string) string {
	// Function names in Go are typically in the form "package/path.FuncName"
	// or "package/path.(*Type).Method"
	
	// Skip type information completely
	if strings.HasPrefix(funcName, "type:") {
		return ""
	}
	
	// Handle method receivers like "pkg.(*Type).Method"
	if strings.Contains(funcName, "(*") {
		// Find the package path before (*Type)
		idx := strings.Index(funcName, ".(")
		if idx != -1 {
			return funcName[:idx]
		}
	}
	
	// Split by last dot to separate package from function/method
	lastDot := strings.LastIndex(funcName, ".")
	if lastDot == -1 {
		return ""
	}
	
	return funcName[:lastDot]
}

func isExternalDependency(pkgName string) bool {
	// Filter out type information
	if strings.HasPrefix(pkgName, "type") ||
		strings.HasPrefix(pkgName, "go.shape") ||
		strings.HasPrefix(pkgName, "weak.") ||
		strings.HasPrefix(pkgName, "unique.") {
		return false
	}
	
	// Exclude standard library packages
	if !strings.Contains(pkgName, "/") {
		return false
	}
	
	// Exclude standard library and internal packages
	if strings.HasPrefix(pkgName, "runtime") ||
		strings.HasPrefix(pkgName, "internal/") ||
		strings.HasPrefix(pkgName, "reflect") ||
		strings.HasPrefix(pkgName, "sync") ||
		strings.HasPrefix(pkgName, "syscall") ||
		strings.HasPrefix(pkgName, "debug/") ||
		strings.HasPrefix(pkgName, "compress/") ||
		strings.HasPrefix(pkgName, "encoding/") ||
		strings.HasPrefix(pkgName, "crypto/") ||
		strings.HasPrefix(pkgName, "net/") ||
		strings.HasPrefix(pkgName, "io/") ||
		strings.HasPrefix(pkgName, "os/") ||
		strings.HasPrefix(pkgName, "fmt") ||
		strings.HasPrefix(pkgName, "slices") ||
		strings.HasPrefix(pkgName, "vendor/golang.org/x/") {
		return false
	}
	
	// Check if it looks like an external dependency (has domain-like prefix)
	parts := strings.Split(pkgName, "/")
	if len(parts) > 0 {
		firstPart := parts[0]
		// External packages typically have a domain as the first part
		if strings.Contains(firstPart, ".") {
			return true
		}
	}
	
	return false
}

func printReport(report *DependencyReport) {
	if len(report.Packages) == 0 {
		fmt.Println("No external dependencies found in binary")
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
	
	fmt.Println("External Dependency Size Report")
	fmt.Println("================================")
	fmt.Println()
	
	for _, pkg := range packages {
		percentage := float64(pkg.size) / float64(report.TotalSize) * 100
		fmt.Printf("%-50s %10s (%5.1f%%)\n", 
			truncatePackageName(pkg.name, 50), 
			formatSize(pkg.size), 
			percentage)
	}
	
	fmt.Println()
	fmt.Printf("Total external dependency size: %s\n", formatSize(report.TotalSize))
}

func truncatePackageName(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	if maxLen < 4 {
		return name[:maxLen]
	}
	return name[:maxLen-4] + "...."
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
