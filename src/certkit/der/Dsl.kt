package certkit.der

import java.math.BigInteger
import kotlin.time.Instant
import kotlinx.io.*

@DslMarker public annotation class DerDsl

@DerDsl
public class DerBuilder {
  internal val elements = mutableListOf<ByteArray>()

  public fun boolean(value: Boolean) {
    elements += Der.boolean(value)
  }

  public fun bitString(padBits: Int, value: ByteArray) {
    elements += Der.bitString(padBits, value)
  }

  public fun integer(value: Long) {
    elements += Der.integer(value)
  }

  public fun integer(value: BigInteger) {
    elements += Der.integer(value)
  }

  public fun nullValue() {
    elements += Der.nullValue
  }

  public fun octetString(value: ByteArray) {
    elements += Der.octetString(value)
  }

  public fun oid(oid: String) {
    elements += Der.oid(oid)
  }

  public fun utcTime(value: String) {
    elements += Der.utcTime(value)
  }

  public fun utcTime(value: Instant) {
    elements += Der.utcTime(value)
  }

  public fun tag(tag: Int, body: ByteArray) {
    elements += Der.tag(tag, body)
  }

  public fun tag(tag: Int, value: String): Unit = tag(tag, value.encodeToByteArray())

  public fun implicitTag(tag: Int, body: ByteArray) {
    elements += Der.implicitTag(tag, body)
  }

  public fun seq(block: DerBuilder.() -> Unit) {
    elements += certkit.der.seq(block)
  }

  public fun set(block: DerBuilder.() -> Unit) {
    elements += certkit.der.set(block)
  }

  public fun octetString(block: DerBuilder.() -> Unit) {
    elements += certkit.der.octetString(block)
  }

  public fun explicitTag(tag: Int, block: DerBuilder.() -> Unit) {
    elements += certkit.der.explicitTag(tag, block)
  }

  public fun raw(value: ByteArray) {
    elements += value
  }
}

private fun der(block: DerBuilder.() -> Unit) = DerBuilder().apply(block).elements.toTypedArray()

public fun seq(block: DerBuilder.() -> Unit): ByteArray = Der.sequence(*der(block))

public fun set(block: DerBuilder.() -> Unit): ByteArray = Der.set(*der(block))

public fun octetString(block: DerBuilder.() -> Unit): ByteArray =
    Der.octetString(Buffer().apply { der(block).forEach { write(it) } }.readByteArray())

public fun explicitTag(tag: Int, block: DerBuilder.() -> Unit): ByteArray =
    Der.explicitTag(tag, *der(block))
