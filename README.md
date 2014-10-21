## Time-Lapse Cryptography

[![Build Status](https://travis-ci.org/tensorjack/time-lapse-crypto.svg)](https://travis-ci.org/tensorjack/time-lapse-crypto)

[Alan Lu's](https://github.com/cag) _time-lapse cryptography protocol_ (TLCP) implementation, which was originally outlined by [Rabin and Thorpe](http://www.eecs.harvard.edu/~cat/tlc.pdf).

### Usage

We use CMake for installation.  To install, just run the included build script:

    $ ./mkbuild.sh

This build script installs the TLCP daemon successfully on Ubuntu and ArchLinux.  After compiling, the `tlcd` binary will be in the `build` directory, and can be run from the terminal:

    $ build/tlcd
