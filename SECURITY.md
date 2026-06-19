# Security Policy

`libomemo.js` implements the cryptographic core of OMEMO (XEP-0384), the
Double Ratchet, X3DH session establishment, and the underlying
Curve25519/XEdDSA primitives, and is depended on by downstream XMPP clients.

Vulnerabilities here can affect the confidentiality, integrity, and
authenticity of users' end-to-end-encrypted messages, so we take them
seriously and welcome reports.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through either channel:

1. **GitHub private vulnerability reporting (preferred).** Open a report at
   <https://github.com/conversejs/libomemo.js/security/advisories/new>. This
   keeps the discussion private until a fix is published and lets us
   coordinate a release with you.
2. **Email.** If you cannot use GitHub, email **jc@amboss.tech**. You can
   encrypt the report to the maintainer's PGP key (see [PGP Key](#pgp-key)).

Please include as much of the following as you can:

- A description of the issue and its security impact (e.g. loss of forward
  secrecy, message forgery, key recovery, authentication bypass, DoS).
- The affected version(s), file(s), and code path(s).
- Step-by-step reproduction instructions, a proof of concept, or a failing
  test if you have one.
- Any known mitigations or workarounds.

You do not need a complete analysis to report. A credible description of a
plausible weakness is enough for us to investigate.

## PGP Key

To encrypt a report, use the maintainer's OpenPGP key:

- **Fingerprint:** `2C06 722D 6280 2D60 4100  1B85 D48D 88C4 1B3A 34E6`
- **User ID:** `JC Brand <jc@amboss.tech>`
- **Type:** RSA-4096, valid until 2030-08-31

**Verify this fingerprint out of band** before trusting any downloaded copy of
the key — the fingerprint above is the trust anchor, not the file or keyserver.
You can obtain the public key from:

- the [`SECURITY.asc`](./SECURITY.asc) file in this repository, or
- a keyserver:
  `gpg --keyserver hkps://keys.openpgp.org --recv-keys 2C06722D62802D6041001B85D48D88C41B3A34E6`

## Our Process

- **Acknowledgement:** we aim to acknowledge a report within **3 business days**.
- **Assessment:** we will confirm the issue, determine severity and affected
  versions, and keep you updated on progress.
- **Coordinated disclosure:** we will agree a disclosure timeline with you. Our
  target is to ship a fix within **90 days** of acknowledgement; genuinely
  critical issues are prioritised well inside that window. We will credit
  reporters who wish to be named, and publish a GitHub Security Advisory (with
  a CVE where warranted) when the fix is released.

Please give us a reasonable opportunity to remediate before any public
disclosure.

## Supported Versions

Security fixes are applied to the latest released `2.x` line. Older releases
(`< 2.0`) do not receive security updates — see [`MIGRATION.md`](./MIGRATION.md)
for upgrade guidance.

| Version | Supported          |
| ------- | ------------------ |
| `2.x`   | :white_check_mark: |
| `< 2.0` | :x:                |

## Scope and Trust Model

This is a library, not a complete OMEMO client, and some security properties
are by design the responsibility of the consuming application. Understanding
the boundary helps direct reports to the right project.

**In scope** (please report):

- Cryptographic defects in the Double Ratchet, X3DH, or the Curve25519/XEdDSA
  primitives (e.g. incorrect key derivation, nonce/IV misuse, signature or MAC
  verification flaws, missing authentication).
- Memory-safety issues in the vendored native code under `native/`.
- Parsing/deserialization flaws reachable from attacker-influenced input
  (wire messages, key bundles, or persisted session state).
- Side channels in the library's own comparisons or key handling.

**Out of scope here** (handle in the consuming application, not this library):

- **Trust decisions.** The library follows a trust-on-first-use (TOFU) model:
  `isTrustedIdentity` is delegated to the consumer-provided store, and the
  library does not itself enforce a trust policy (e.g. blind trust vs. manual
  fingerprint verification). First-contact MITM is mitigated only by
  out-of-band fingerprint verification, for which the library provides
  `FingerprintGenerator`. Enforcing a policy is the consumer's responsibility.
- **At-rest protection of the session/identity store.** The `OMEMOStore`
  implementation (key material, session records) is provided by the consumer;
  protecting it is theirs to do.
- **Transport security and XMPP-layer concerns**, including device-list
  management, prekey replenishment, and message routing.

If you are unsure whether something is in scope, report it privately anyway and
we will help route it.
