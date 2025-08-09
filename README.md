# WILDBEAST

## BRIEF

Project `WILDBEAST` is an effort to tame the `GCC toolchain` for `Windows` capability development.

There are currently three `C/C++` template projects for building an `EXE`, a `DLL`, or a `PIC` blob in their respective subdirectories with a unified `GNU Makefile`.

## SETUP

[GNU-Toolchain-Setup-Windows](https://gist.github.com/winterknife/0b177a75a55bad895b19aad64cffa14f)

## BUILD

```powershell
git clone https://github.com/winterknife/WILDBEAST.git
cd .\WILDBEAST\MessageBox{EXE|DLL|PIC}\
$env:CHERE_INVOKING = 'yes'
$env:MSYSTEM = 'MINGW64'
C:\msys64\usr\bin\bash -lc 'make clean && make {exe|dll|pic}'
```

## CI BUILD

[build.yml](.github/workflows/build.yml)