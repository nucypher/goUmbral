# goUmbral

goUmbral is a Go implementation of David Nuñez's threshold proxy re-encryption scheme: [Umbral][1].
Implemented with [OpenSSL][2], goUmbral is an open-source cryptography library based on the referential
python library, [pyUmbral][3].

[1]: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf  "Umbral"
[2]: https://www.openssl.org/                                           "OpenSSL"
[3]: https://github.com/nucypher/pyUmbral/                              "pyUmbral"

goUmbral is still in major development and the API in considered unstable. It will be changing a lot.

Quick Installation
------------------

OpenSSL is a required dependency. OpenSSL versions 1.1.0+ work but it is recommended to install OpenSSL version 1.1.1.

Install OpenSSL system wide or link to your local installation in the build.go file of umbral.

The NuCypher team uses Go for managing goUmbral's dependencies.
The recommended installation procedure is as follows:

`go get https://github.com/nucypher/goUmbral/`

Then just include the package at the top of your file:

`import "github.com/nucypher/goUmbral/umbral"`

Academic Whitepaper
-------------------

The Umbral scheme academic whitepaper and cryptographic specifications
are available on [GitHub][1].

> "Umbral: A Threshold Proxy Re-Encryption Scheme"
> *by David Nuñez* https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

Support & Contribute
--------------------

- Issue Tracker: https://github.com/nucypher/goUmbral/issues
- Source Code: https://github.com/nucypher/goUmbral

OFAC Sanctions Disclaimer
-------------------------

By using this software, you hereby affirm you are not an individual or entity subject to economic sanctions administered by the U.S. Government or any other applicable authority, including but not limited to, sanctioned party lists administered by the U.S. Treasury Department’s Office of Foreign Assets Control (OFAC), the U.S. State Department, and the U.S. Commerce Department.  You further affirm you are not located in, or ordinarily resident in, any country, territory or region subject to comprehensive economic sanctions administered by OFAC, which are subject to change but currently include Cuba, Iran, North Korea, Syria and the Crimea region.
