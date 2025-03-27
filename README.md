# SQISign-Go

This is a repository for Go bindinds of the [SQISign](https://github.com/SQISign/the-sqisign) algorithm made in C using CGo.

## Getting Started

First, clone the `sqisign-go` repository:

```bash
$ git clone git@github.com:PQC-Group-UTFPR/sqisign-go.git
$ cd sqisign-go
```

Build the external library:

```bash
$ ./build.sh
```

### Examples

```bash
$ cd src/main
$ go build -tags lvl<1/3/5>
$ ./main
```
