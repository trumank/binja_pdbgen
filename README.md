# binja_pdbgen

A Binary Ninja plugin that generates PDB files from analyzed PE executables which enables debuggers and other RE tools to leverage Binary Ninja's database.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/binja_pdbgen.git
   cd binja_pdbgen
   ```

2. Build the plugin:
   ```bash
   cargo build --release
   ```

3. Copy the built library to your Binary Ninja plugins directory:
   - **Windows**: `target/release/binja_pdbgen.dll`
   - **Linux**: `target/release/libbinja_pdbgen.so`
   - **macOS**: `target/release/libbinja_pdbgen.dylib`

## Usage

1. Open a PE executable in Binary Ninja
2. Navigate to **Plugins → Generate PDB**
3. The PDB file will be created next to the original executable

## Limitations

- Currently generates all functions as `void()`. Could be extended to support args and other return types.
- Poor handling of non-linear functions (exports as multiple functions with `_partN` suffix)
- Limited testing. Seems to work for x64dbg, Binary Ninja itself, and WINE. WinDbg and Windows itself untested.

## Acknowledgments

- jac3km4's [pdb-sdk](https://github.com/jac3km4/pdb-sdk) library which was a great starting point
- [FakePDB](https://github.com/Mixaill/FakePDB) which implements similar functionality for IDA and the original idea
