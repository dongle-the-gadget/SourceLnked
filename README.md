# SourceLnked

Inspects Source Linked and Source Server metadata in PDB symbols.
Supports both Portable PDBs (.NET Core/.NET 5+) and Windows PDBs (tested with C++).

## Usage

```
SourceLnked [PDB file]
```

## License

[MIT](LICENSE.md)

## Acknowledgements

This project wouldn't be possible without the following people:
- [Cameron Taggart (ctaggart)](https://github.com/ctaggart), for developing Source Link.
- [Washi](https://github.com/Washi1337) and contributors, for developing [AsmResolver](https://github.com/Washi1337/AsmResolver), which is used to parse PDB files.
- [Markus Stange (mstange)](https://github.com/mstange), for developing a [Source Server metadata parser in Rust](https://github.com/mstange/srcsrv), and gathering specifications for Source Server which I used.