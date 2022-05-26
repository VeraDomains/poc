# Vera PoC Learnings

## Dependencies

### Libraries

We could leverage the following third-party libraries:

- On Android and the JVM:
  - `dnsjava` for DNSSEC verification.
- On JS:
  - .

We'll have to build the following libraries:

- DNSSEC verification (JS). [netkicorp/dnssecjs](https://github.com/netkicorp/dnssecjs) is the only JS implementation we could find, but was abandoned in 2017 as soon as it was published on GitHub, and it wouldn't be wise to fork it for several reasons:
  - We'd basically have to rewrite it: It's not the most maintainable code around, it uses very old JS, it supports insecure cryptographic algorithms (e.g., SHA-1), it implements some low-level cryptographic/networking routines that should be delegated to external libraries, etc.
  - There are zero tests.
  - We'd only need a subset of the library: [`dnssec-verifier.js`](https://github.com/netkicorp/dnssecjs/blob/c6679ca6c71d076e4f59c2f2a9c6df150df1b59e/lib/dnssec-verifier.js) and part of [`utils.js`](https://github.com/netkicorp/dnssecjs/blob/c6679ca6c71d076e4f59c2f2a9c6df150df1b59e/lib/utils.js).
- Relaycorp `crypto` libraries (JS and JVM), by factoring out some code from the Awala core libraries -- namely, the code involving X.509 `Certificate`s, CMS `SignedData` values and RSA keys. We may want to migrate CMS `EnvelopedData` too for consistency.

### Third-party tools

### Third-party services

### Relaycorp libraries

- Awala core.
 