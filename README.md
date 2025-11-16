# gobinsize

A Go program that analyzes Go binaries to determine how much of their size can be attributed to external dependencies.

## Installation

```bash
go install github.com/imjasonh/gobinsize@latest
```

Or build from source:

```bash
git clone https://github.com/imjasonh/gobinsize.git
cd gobinsize
go build -o gobinsize .
```

## Usage

```bash
gobinsize <path-to-binary>
```

### Example

```bash
$ gobinsize ./myapp
External Dependency Size Report
================================

github.com/gorilla/mux                               11.38 KB ( 83.5%)
github.com/gorilla/mux.routeRegexpGroup               2.25 KB ( 16.5%)

Total external dependency size: 13.62 KB
```

## How It Works

gobinsize analyzes Go binaries by:

1. Parsing the binary's debug information (supports ELF, Mach-O, and PE formats)
2. Extracting the Go symbol table and pclntab (program counter line table)
3. Identifying functions and their associated packages
4. Filtering out standard library packages to focus on external dependencies
5. Calculating the size contribution of each external dependency
6. Generating a sorted report showing dependency sizes

## Supported Platforms

- Linux (ELF binaries)
- macOS (Mach-O binaries)  
- Windows (PE binaries)

## Notes

- The binary must be built with Go and contain debug information
- Size measurements are based on function code sizes from the symbol table
- Only external dependencies (packages with domain names like github.com, golang.org, etc.) are reported
- Standard library packages are filtered out from the report