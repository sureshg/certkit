<p align="center">
  <img src="docs/banner.png" alt="certkit"/>
</p>

[![GitHub Workflow Status][gha_badge]][gha_url]
[![Maven Central Version][maven_img]][maven_url]
[![Kotlin release][kt_img]][kt_url]
[![OpenJDK Version][java_img]][java_url]
[![Test Report][test_img]][test_url]

Lightweight X.509 certificate toolkit for Kotlin/JVM. Build self-signed certs, CSRs, CRLs, and work with PEM/DER
encoding, all using JDK standard libraries. No BouncyCastle, no Guava.

## Features

- **Self-signed certificates** — X.509v3 with SAN, Basic Constraints, key identifiers (EC keys)
- **CSR creation** — PKCS#10 Certificate Signing Requests with SAN support
- **CRL support** — parse, build, and check certificate revocation lists
- **PEM read/write** — load and encode certificates, private keys, public keys
- **DER DSL** — type-safe Kotlin DSL for building ASN.1 DER structures
- **Private key formats** — PKCS#8, PKCS#8 encrypted, PKCS#1 (RSA, DSA, EC)
- **TLS scanning** — connect to any host and capture the certificate chain

## 🚀 Quick Start

> **Requires JDK 21+**

<details open>
<summary><strong>Kotlin Toolchain</strong></summary>

```yaml
dependencies:
  - dev.suresh.certkit:certkit:LATEST_VERSION
```

</details>

<details>
<summary><strong>Gradle</strong></summary>

```kotlin
dependencies {
    implementation("dev.suresh.certkit:certkit:LATEST_VERSION")
}
```

</details>

<details>
<summary><strong>Maven</strong></summary>

```xml

<dependency>
    <groupId>dev.suresh.certkit</groupId>
    <artifactId>certkit</artifactId>
    <version>LATEST_VERSION</version>
</dependency>
```

</details>

### Self-Signed Certificate

```kotlin
val keyPair = newEcKeyPair()
val today = Clock.System.todayIn(TimeZone.UTC)

val cert = Cert.buildSelfSigned(
    keyPair = keyPair,
    serialNumber = 1,
    issuer = X500Principal("CN=My CA,O=TestOrg"),
    subject = X500Principal("CN=My CA,O=TestOrg"),
    notBefore = today,
    notAfter = today + DatePeriod(days = 30),
    sans = [San.Dns("localhost"), San.Dns("*.local"), San.Ip("127.0.0.1")],
)

println(cert.pem)
```

An `Instant` overload is also available for precise control over validity times.

### Certificate Extensions

```kotlin
cert.commonName          // "My CA"
cert.subjectAltNames     // ["localhost", "*.local", "127.0.0.1"]
cert.expiryDateUtc       // 2026-04-07T23:59:59
cert.isExpired           // false
cert.expiresIn           // 30d 0h ...
cert.isCA                // true
cert.selfSigned          // true
cert.signedBy(caCert)    // true
```

### PEM

```kotlin
// Load
val privateKey = Pem.loadPrivateKey(Path("server.key"), keyPassword = "secret")
val publicKey = Pem.loadPublicKey(Path("server.pub"))
val certs = Pem.readCertificateChain(Path("chain.crt"))
val keyStore = Pem.loadKeyStore(Path("server.crt"), Path("server.key"))
val trustStore = Pem.loadTrustStore(Path("ca.crt"))

// Encode — .pem extension on all major types
publicKey.pem                              // -----BEGIN PUBLIC KEY-----
privateKey.pem                             // -----BEGIN PRIVATE KEY-----
certificate.pem                            // -----BEGIN CERTIFICATE-----
csr.pem                                    // -----BEGIN CERTIFICATE REQUEST-----
crl.pem                                    // -----BEGIN X509 CRL-----

// PKCS#8 export (encrypted & unencrypted)
privateKey.toPkcs8Pem()                    // -----BEGIN PRIVATE KEY-----
privateKey.toPkcs8Pem(password = "secret") // -----BEGIN ENCRYPTED PRIVATE KEY-----

// PKCS#1 export (RSA only)
rsaPrivateKey.toPkcs1Pem()                 // -----BEGIN RSA PRIVATE KEY-----
```

### KeyStore

```kotlin
// Parse a Base64-encoded PKCS#12 keystore into PEM components
val bundle = parseKeyStore(base64Data, storePass = "changeit")
// Export with encrypted PKCS#8 key
val encrypted = parseKeyStore(base64Data, "changeit", format = KeyFormat.Pkcs8(keyPass = "secret"))
// Export with PKCS#1 key (RSA only, no encryption)
val pkcs1 = parseKeyStore(base64Data, "changeit", format = KeyFormat.Pkcs1)

// PemBundle fields
bundle.key        // PEM-encoded private key
bundle.cert       // PEM-encoded leaf certificate
bundle.certChain  // PEM-encoded CA certificate chain
bundle.keyPass    // key password
```

### CSR

```kotlin
val csr = Csr.create(
    x500Name = "CN=app.example.com,O=Acme",
    algorithmName = "SHA256withRSA",
    keyPair = keyPair,
    sans = [San.Dns("app.example.com"), San.Ip("10.0.0.1")],
)
println(csr.pem)
```

### CRL

```kotlin
val crl = Crl.build(
    keyPair = caKeyPair,
    issuer = X500Principal("CN=My CA,O=Acme"),
    thisUpdate = Clock.System.now(),
    nextUpdate = Clock.System.now() + 30.days,
    revokedSerials = [42L, 99L],
)

cert.isRevokedBy(crl)          // check revocation
Crl.distributionPoints(cert)   // extract CRL URLs
```

### DER DSL

Type-safe Kotlin DSL for building ASN.1 DER-encoded structures:

```kotlin
val encoded: ByteArray = seq {
    integer(1L)
    boolean(true)
    seq {
        oid("2.5.29.14")
        octetString([0x01, 0x02])
    }
    utcTime(Clock.System.now())
    explicitTag(0) { integer(2L) }
}
```

All standard ASN.1 types are supported: `integer`, `boolean`, `bitString`, `octetString`, `oid`,
`utcTime`, `nullValue`, `tag`, `implicitTag`, `explicitTag`, `seq`, and `set`.

### TLS

```kotlin
// Scan remote server certificates
val chain = scanCertificates("github.com")
chain.forEach { println("${it.commonName} — expires ${it.expiryDateUtc}") }

```

## Supported Types

| Category       | Formats                                         |
|----------------|-------------------------------------------------|
| Private keys   | PKCS#8, PKCS#8 encrypted, PKCS#1 (RSA, DSA, EC) |
| Public keys    | X.509/SPKI, PKCS#1 RSA                          |
| Certificates   | X.509v3 (PEM & DER)                             |
| CRLs           | X.509 CRL (PEM & DER)                           |
| Key algorithms | RSA, EC (secp256r1, secp384r1, …), DSA          |
| Cert builder   | EC keys (SHA256withECDSA)                       |

## 🔧 Build & Test

```bash
$ ./kotlin build                # Build
$ ./kotlin test                 # Test
$ ./kotlin publish mavenLocal   # Publish to local Maven repository
```

## 📦 Release

Push a version tag to publish to Maven Central and create a GitHub release:

```bash
$ git tag -am "Release v1.0.0" v1.0.0
$ git push origin --tags
```

## Credits

Thanks to the [Airlift](https://github.com/airlift/airlift) project. The crypto and DER/PEM logic is adapted from its
security module, rewritten as idiomatic Kotlin without the Guava dependency.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

<!-- Badges -->

[gha_url]: https://github.com/sureshg/certkit/actions/workflows/build.yaml

[gha_badge]: https://img.shields.io/github/actions/workflow/status/sureshg/certkit/build.yaml?branch=main&style=flat&logo=kotlin&logoColor=3BEA62&label=Kotlin%20Build

[java_url]: https://www.azul.com/downloads/?version=java-25-lts&package=jdk#zulu

[java_img]: https://img.shields.io/badge/OpenJDK-25-e76f00?logo=openjdk&logoColor=e76f00

[kt_url]: https://github.com/JetBrains/kotlin/releases/latest

[kt_img]: https://img.shields.io/github/v/release/Jetbrains/kotlin?include_prereleases&color=7f53ff&label=Kotlin&logo=kotlin&logoColor=7f53ff

[test_url]: https://suresh.dev/certkit/reports/

[test_img]: https://img.shields.io/badge/Test_Report-passing-4c1?logo=junit5&logoColor=white

[maven_url]: https://central.sonatype.com/artifact/dev.suresh.certkit/certkit

[maven_img]: https://img.shields.io/maven-central/v/dev.suresh.certkit/certkit?logo=apachemaven&logoColor=C71A36&color=C71A36&label=Maven%20Central

[kt_toolchain_url]: https://kotlin-toolchain.org/dev/

[kt_toolchain_img]: https://img.shields.io/badge/Build-Kotlin%20Toolchain-3BEA62?logo=kotlin&logoColor=3BEA62
