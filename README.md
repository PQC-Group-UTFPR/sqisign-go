# SQISign-Go

This is a repository for Go bindinds of the [SQISign](https://github.com/SQISign/the-sqisign) algorithm made in C using CGo.

## Building the C SQISign
In the **Build** section of [SQISign](https://github.com/SQISign/the-sqisign/blob/main/README.md), we recommend using the following *cmake* flags:  
```bash
cmake -DSQISIGN_BUILD_TYPE=ref ENABLE_TESTS=OFF ENABLE_GMP_BUILD=ON ..
```

## Building the Go SQISign
In the [sqisign.go](src/sqisign/sqisign.go) replace the `<absolute_path_sqisign>` with the correct absolute path to the SQISign C repository, e.g., `/home/user/git/the-sqisign`

Then, to build the executable we need two steps.
First, select the desired security level, i.e., `1`, `3` or `5`. To do that, change the line:
```C
#define SECURITY_LEVEL 3
```
and replace with the desired security level.

Second, to build the example executable, go to the [main package](src/main) and run the following command with the same level selected in the C directive, choosing between `lvl1`, `lvl3` and `lvl5`.
```bash
go build -tags 'lvl<1/3/5>'
```
