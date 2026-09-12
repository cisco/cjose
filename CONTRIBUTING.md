# Contributing #

## Before Submitting PR ##

* Run `cmake --build build --target clang-format`
* Run `ctest --test-dir build --output-on-failure -V`

The project requires CMake 3.22 or newer. Configure a build directory with
`cmake -S . -B build` before running the commands above.
