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
gobinsize [-verbose] [-svg output.svg] <path-to-binary>
```

### Options

- `-verbose`: Enable verbose logging for debugging symbol attribution
- `-svg <file>`: Generate an SVG treemap visualization of dependencies

### Example

```bash
$ gobinsize ./myapp
Dependency Size Report
======================

github.com/gorilla/mux                               13.62 KB ( 18.8%)
gopkg.in/yaml.v2                                     52.38 KB ( 72.1%)
net                                                   6.59 KB (  9.1%)

Total size: 72.59 KB
```

### SVG Treemap Visualization

Generate a visual treemap to see your dependencies at a glance:

```bash
$ gobinsize -svg dependencies.svg ./myapp
Dependency Size Report
======================
...
SVG treemap written to dependencies.svg
```

The treemap uses colors to distinguish packages and sizes rectangles proportionally to each dependency's contribution to the binary size.

## How It Works

gobinsize analyzes Go binaries by:

1. Parsing the binary's debug information (supports ELF, Mach-O, and PE formats)
2. Extracting the Go symbol table and pclntab (program counter line table)
3. Identifying functions and their associated packages/modules
4. Aggregating sizes by top-level module (e.g., github.com/user/repo) or standard library package
5. Calculating the size contribution of each dependency
6. Generating a sorted report showing dependency sizes

## Supported Platforms

- Linux (ELF binaries)
- macOS (Mach-O binaries)
- Windows (PE binaries)

## Notes

- The binary must be built with Go and contain debug information
- Size measurements are based on function code sizes from the symbol table
- Includes all dependencies: standard library, external packages (github.com, gopkg.in, etc.), and golang.org/x packages
- Dependencies are aggregated by module/top-level package for cleaner output