<p align="center">
  <img src="docs/banner.png" alt="certkit"/>
</p>

[![Kotlin release][kt_img]][kt_url]
[![OpenJDK Version][java_img]][java_url]
[![Build-Amper][amper_img]][amper_url]

Lightweight X.509 certificate toolkit for Kotlin/JVM. Build self-signed certs, CSRs, CRLs, and work with PEM/DER
encoding, all using JDK standard libraries.

## Features

- **Self-signed certificates** — X.509v3 with SAN, Basic Constraints, key identifiers (EC keys)
- **CSR creation** — PKCS#10 Certificate Signing Requests with SAN support
- **CRL support** — parse, build, and check certificate revocation lists; extract CRL Distribution Points
- **PEM read/write** — load and encode certificates, private keys, public keys
- **Private key formats** — PKCS#8 unencrypted, PKCS#8 PBE-encrypted, PKCS#1 (RSA, DSA, EC)
- **TLS scanning** — connect to any host and capture the certificate chain
- **No BouncyCastle, no Guava** — all crypto is pure JDK `java.security.*` and `javax.crypto.*`

## Supported Types

- **Private keys** — PKCS#8, PKCS#8 encrypted, PKCS#1 (RSA, DSA, EC)
- **Public keys** — X.509/SPKI, PKCS#1 RSA
- **Certificates** — X.509v3 (PEM & DER)
- **CRLs** — X.509 CRL (PEM & DER)
- **Key algorithms** — RSA, EC (secp256r1, secp384r1, …), DSA
- **Cert builder** — EC keys (SHA256withECDSA)

## 🚀 Quick Start

> **Requires JDK 21+**

Add the dependency:

```kotlin
dependencies {
    implementation("dev.suresh.certkit:certkit:1.0.0-SNAPSHOT")
}
```

### Self-Signed Certificate

```kotlin
val keyPair = KeyPairGenerator.getInstance("EC")
    .apply { initialize(ECGenParameterSpec("secp256r1")) }
    .generateKeyPair()

val cert = Cert.buildSelfSigned(
    keyPair = keyPair,
    serialNumber = 1,
    issuer = X500Principal("CN=My CA,O=Acme"),
    subject = X500Principal("CN=My CA,O=Acme"),
    notBefore = LocalDate(2025, 1, 1),
    notAfter = LocalDate(2026, 12, 31),
    sans = listOf(San.Dns("localhost"), San.Dns("*.local"), San.Ip("127.0.0.1")),
)

println(cert.pem)
```

### Create a CSR

```kotlin
val keyPair = KeyPairGenerator.getInstance("RSA")
    .apply { initialize(2048) }
    .generateKeyPair()

val csr = Csr.create(
    x500Name = "CN=app.example.com,O=Acme",
    algorithmName = "SHA256withRSA",
    keyPair = keyPair,
    sans = listOf(San.Dns("app.example.com"), San.Ip("10.0.0.1")),
)
println(csr.encoded)
```

### Build & Check a CRL

```kotlin
val crl = Crl.build(
    keyPair = caKeyPair,
    issuer = X500Principal("CN=My CA,O=Acme"),
    thisUpdate = Clock.System.now(),
    nextUpdate = Clock.System.now() + 30.days,
    revokedSerials = listOf(42L, 99L),
)

// Check if a certificate is revoked
val revoked = cert.isRevokedBy(crl)

// Extract CRL Distribution Points from a certificate
val urls = Crl.distributionPoints(cert)
```

### Load PEM Keys & Certificates

```kotlin
val privateKey = Pem.loadPrivateKey(Path("server.key"), keyPassword = "secret")
val publicKey = Pem.loadPublicKey(Path("server.pub"))
val certs = Pem.readCertificateChain(Path("chain.crt"))
val keyStore = Pem.loadKeyStore(Path("server.crt"), Path("server.key"))
val trustStore = Pem.loadTrustStore(Path("ca.crt"))
```

### Scan TLS Certificates

```kotlin
val chain = scanCertificates("github.com")
chain.forEach { println("${it.commonName} — expires ${it.expiryDateUTC}") }
```

### PEM Encoding

```kotlin
println(keyPair.public.pem)     // -----BEGIN PUBLIC KEY-----
println(keyPair.private.pem)    // -----BEGIN PRIVATE KEY-----
println(certificate.pem)        // -----BEGIN CERTIFICATE-----
println(csr.pem)                // -----BEGIN CERTIFICATE REQUEST-----
println(crl.pem)                // -----BEGIN X509 CRL-----
```

## 🔧 Build & Test

```bash
./amper build                 # Build
./amper test                  # Test
./amper publish mavenLocal    # Publish to local Maven repository
```

## Credits

Huge thanks to the [Airlift](https://github.com/airlift/airlift) team. The crypto and DER/PEM logic in this library is a
Kotlin rewrite of the security module, stripped of the Guava dependency and rewritten as idiomatic Kotlin.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

<!-- Badges -->

[java_url]: https://www.azul.com/downloads/?version=java-25-lts&package=jdk#zulu

[java_img]: https://img.shields.io/badge/OpenJDK-25-e76f00?logo=openjdk&logoColor=e76f00

[kt_url]: https://github.com/JetBrains/kotlin/releases/latest

[kt_img]: https://img.shields.io/github/v/release/Jetbrains/kotlin?include_prereleases&color=7f53ff&label=Kotlin&logo=kotlin&logoColor=7f53ff

[amper_url]: https://github.com/JetBrains/amper

[amper_img]: https://img.shields.io/badge/Build-Amper-6B57FF?logo=jetbrains&logoColor=white
