# Acknowledgments

Craton Shield is built by **Craton Software Company** with contributions from
the open-source community and guidance from international standards bodies.

---

## Open Source Dependencies

This project builds on the excellent work of the Rust ecosystem:

| Project / Crate | Usage |
|:---|:---|
| [RustCrypto](https://github.com/RustCrypto) | `aes-gcm`, `sha2`, `hmac`, `p256`, `ecdsa` -- core cryptographic primitives |
| [subtle](https://crates.io/crates/subtle) | Constant-time operations for side-channel resistance |
| [zeroize](https://crates.io/crates/zeroize) | Secure memory erasure to prevent secret leakage |
| [Criterion](https://crates.io/crates/criterion) | Benchmarking framework for performance regression testing |

## Standards and Specifications

Craton Shield is designed with guidance from the following standards and
specifications:

- **ISO/SAE 21434** -- Road Vehicles: Cybersecurity Engineering
- **ISO 26262** -- Road Vehicles: Functional Safety
- **IEC 62443** -- Security for Industrial Automation and Control Systems
- **IEC 62304** -- Medical Device Software: Software Life Cycle Processes
- **AUTOSAR** -- Automotive Open System Architecture (Classic and Adaptive)
- **SAE J1939 / J3061** -- Vehicle network and cybersecurity standards
- **TUF (The Update Framework)** -- Specification for secure software update systems
- **FIPS 140-3** -- Security Requirements for Cryptographic Modules

We thank the **AUTOSAR consortium**, **IEC**, **ISO**, and **SAE** standards
bodies for making their specifications available to the engineering community.

## Community

- **The Rust Programming Language** -- For a systems language that makes
  safety-critical development practical
- **Embedded Rust Working Group** -- For driving `no_std` ecosystem support and
  embedded tooling that Craton Shield depends on
- **Contributor Covenant** -- Our [Code of Conduct](CODE_OF_CONDUCT.md) is
  adapted from the Contributor Covenant
- **RustSec Advisory Database** -- Continuous dependency vulnerability monitoring

## Security Research

- [MITRE CVE](https://cve.mitre.org/) -- CVE identifier coordination
- [OWASP](https://owasp.org/) -- Security best practices guidance

---

If you've contributed to Craton Shield and aren't listed here, please open a PR!
We want to recognize everyone who helps make embedded security better.
