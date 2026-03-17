package certkit.pem

import certkit.resPath
import java.security.PrivateKey
import kotlin.test.*

class PkcsPemTest {

  private val password = "testpass"
  private val keyTypes = listOf("rsa", "ec", "dsa")

  @Test
  fun `toPkcs8Pem unencrypted round-trip for all key types`() {
    keyTypes.forEach { type ->
      val key = loadKey("$type.client.pkcs8.key")
      val pem = key.toPkcs8Pem()
      assertContains(pem, "BEGIN ${PemType.PKCS8INF.marker}")
      assertEquals(key, Pem.loadPrivateKey(pem), "$type key round-trip failed")
    }
  }

  @Test
  fun `toPkcs8Pem encrypted v1 round-trip for all key types`() {
    keyTypes.forEach { type ->
      val key = loadKey("$type.client.pkcs8.key")
      val pem = key.toPkcs8Pem(password, Pkcs8Algo.V1_SHA1_3DES)
      assertContains(pem, "BEGIN ${PemType.PKCS8.marker}")
      assertEquals(key, Pem.loadPrivateKey(pem, password), "$type v1 round-trip failed")
    }
  }

  @Test
  fun `toPkcs8Pem encrypted v2 round-trip for all key types`() {
    keyTypes.forEach { type ->
      val key = loadKey("$type.client.pkcs8.key")
      val pem = key.toPkcs8Pem(password, Pkcs8Algo.V2_AES_256_CBC)
      assertContains(pem, "BEGIN ${PemType.PKCS8.marker}")
      assertEquals(key, Pem.loadPrivateKey(pem, password), "$type v2 round-trip failed")
    }
  }

  @Test
  fun `toPkcs8Pem default algorithm is v1`() {
    val key = loadKey("rsa.client.pkcs8.key")
    val pem = key.toPkcs8Pem(password)
    assertContains(pem, "BEGIN ${PemType.PKCS8.marker}")
    assertEquals(key, Pem.loadPrivateKey(pem, password))
  }

  @Test
  fun `toPkcs8Pem encrypted with wrong password fails`() {
    val key = loadKey("rsa.client.pkcs8.key")
    val pem = key.toPkcs8Pem(password)
    assertFails { Pem.loadPrivateKey(pem, "wrongpassword") }
  }

  @Test
  fun `toPkcs1Pem round-trip for RSA`() {
    val key = loadKey("rsa.client.pkcs8.key")
    val pem = key.toPkcs1Pem()
    assertContains(pem, "BEGIN ${PemType.PKCS1.marker}")
    assertEquals(key, Pem.loadPrivateKey(pem))
  }

  @Test
  fun `toPkcs1Pem fails for non-RSA keys`() {
    assertFailsWith<IllegalStateException> { loadKey("ec.client.pkcs8.key").toPkcs1Pem() }
    assertFailsWith<IllegalStateException> { loadKey("dsa.client.pkcs8.key").toPkcs1Pem() }
  }

  private fun loadKey(name: String): PrivateKey = Pem.loadPrivateKey(resPath(name))
}
