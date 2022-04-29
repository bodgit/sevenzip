[![Build Status](https://travis-ci.com/bodgit/sevenzip.svg?branch=master)](https://travis-ci.com/bodgit/sevenzip)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/sevenzip/badge.svg?branch=master)](https://coveralls.io/github/bodgit/sevenzip?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/bodgit/sevenzip)](https://goreportcard.com/report/github.com/bodgit/sevenzip)
[![GoDoc](https://godoc.org/github.com/bodgit/sevenzip?status.svg)](https://godoc.org/github.com/bodgit/sevenzip)

sevenzip
========

A very rough attempt at a reader for 7-zip archives inspired by `archive/zip`.

Current status:

* Pure Go, no external libraries or binaries needed.
* Handles uncompressed headers, (`7za a -mhc=off test.7z ...`).
* Handles compressed headers, (`7za a -mhc=on test.7z ...`).
* Handles password-protected versions of both of the above (`7za a -mhc=on|off -mhe=on -ppassword test.7z ...`).
* Handles archives split into multiple volumes, (`7za a -v100m test.7z ...`).
* Validates CRC values as it parses the file.
* Supports BCJ2, Bzip2, Copy, Deflate, Delta, LZMA and LZMA2 methods.

More examples of 7-zip archives are needed to test all of the different combinations/algorithms possible.
