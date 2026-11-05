# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| 0.2.x   | No        |
| < 0.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in memseal, **please do not open a public issue**.

Instead, report it privately via email to **samjanny@gmail.com** with the subject line `[memseal] Security vulnerability`.

Please include:
- A description of the vulnerability
- Steps to reproduce or a proof of concept
- Impact assessment (what an attacker could achieve)
- Affected version(s)

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before public disclosure.

## Scope

The following are in scope for security reports:
- Cryptographic weaknesses (nonce reuse, key leakage, authentication bypass)
- Memory safety issues (use-after-free, buffer overflows in unsafe blocks)
- Key material exposure (keys not zeroized, leaked to logs/debug output)
- Denial of service via crafted vault files (resource exhaustion, panics on untrusted input)
- Dependency vulnerabilities that directly affect memseal

The following are out of scope:
- Attacks requiring kernel/root access (memseal is a user-space library)
- Side-channel attacks on the CPU (Spectre, cache timing)
- Social engineering

Note on `open()` and `load()`: the KDF parameters come from the unauthenticated header, so a hostile file can always cost one Argon2id derivation before it is rejected. That derivation is bounded to 256 MiB and 10 passes (`DESIGN.md` section 10.1); cost within that bound is by design and not a vulnerability, cost beyond it is.

## Security Audit Status

This library has **not been independently audited**. It uses well-established cryptographic primitives (XChaCha20-Poly1305 and HKDF-SHA256 from the [orion](https://crates.io/crates/orion) crate, Argon2id from the RustCrypto [argon2](https://crates.io/crates/argon2) crate), but the integration layer has not been reviewed by a third-party security firm.

Vault files written by releases up to 0.2.1 were keyed with Argon2i, the only variant `orion` implements and the weaker one against offline GPU cracking of a stolen file. Such files are re-keyed with Argon2id the first time they are opened and saved by a current release; until then they keep the weaker KDF.

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:
1. Release a patched version
2. Publish a RustSec advisory if applicable
3. Credit the reporter (unless anonymity is requested)
