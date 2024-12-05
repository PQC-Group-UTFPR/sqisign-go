# sqisign-go

`sqisign-go` is a Go wrapper around the SQISign cryptographic library. It
provides functionality to generate keypairs, sign messages, and verify
signatures using the SQISign post-quantum signature algorithm. The wrapper
integrates with the `libsqisign_lvl1.a` static library from the SQISign project.

## ⚠️ Current Status

**This repository is in stand-by mode.** The SQISign algorithm implementation
contains unresolved issues regarding its build, as noted in the [SQISign
GitHub issue #4](https://github.com/SQISign/the-sqisign/issues/4). Therefore,
this wrapper will not work until these issues are resolved.

## Getting Started

### Prerequisites

Ensure you have the following installed on your system:
- GCC with support for modern standards.
- Go programming language (version 1.15+ recommended).
- CMake for building the external library.

### Clone the Repository

First, clone the `sqisign-go` repository:

```bash
git clone --recurse-submodules https://github.com/gabrielzschmitz/sqisign-go.git
cd sqisign-go
```

If you have already cloned the repository without submodules, you can initialize
and update them using:

```bash
git submodule update --init --recursive
```

### Build the External Library

The Go wrapper depends on the `libsqsisign_lvl1.a` static library, which needs
to be built from the SQISign project.

To build the library:

1. Navigate to the SQISign project directory:
   ```bash
   cd external/the-sqisign
   ```
2. Create a build directory and configure the project with CMake:
   ```bash
   mkdir -p build
   cd build
   cmake -DSQISIGN_BUILD_TYPE=ref ..
   make
   ```

This will generate necessary librarys inside `build/src/`.

### Build the Go Project

Once the library is built, you can compile and run the Go project!

```bash
go build .
go run .
```

### Notes
- Ensure the library paths in `CGO_CFLAGS` and `CGO_LDFLAGS` are adjusted to
  match your build directory structure.
- See the [⚠️ Current Status](#⚠️-current-status) section for details about the
  upstream issue affecting this repository.

## License

This project is licensed under the MIT License.
