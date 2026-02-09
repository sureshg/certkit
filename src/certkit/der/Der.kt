package certkit.der

import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format
import kotlinx.datetime.format.char
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import java.math.BigInteger
import kotlin.time.Instant

/**
 * ASN.1 DER (Distinguished Encoding Rules) encoder/decoder — the binary format
 * used inside X.509 certificates, CSRs, and keys.
 *
 * Every DER element is a **Tag-Length-Value** (TLV) triplet:
 * ```
 *  ┌─────┐ ┌────────┐ ┌───────────────┐
 *  │ Tag │ │ Length │ │    Value …    │
 *  └─────┘ └────────┘ └───────────────┘
 * ```
 *
 * **How length is encoded:**
 * - **≤ 127** → single byte:  `writeLength(5) → [0x05]`
 * - **≥ 128** → first byte = `0x80 + N` (N = number of following length bytes):
 *   `writeLength(256) → [0x82, 0x01, 0x00]`  (0x82 means "2 bytes follow")
 *
 * **How OIDs are encoded** (e.g. `"1.2.840.113549"`):
 * - First two arcs merged: `arc0 * 40 + arc1` → single byte
 * - Each remaining arc → base-128 varint (high bit = "more bytes follow")
 */
object Der {

  private const val SEQUENCE_TAG = 0x30
  private const val BOOLEAN_TAG = 0x01
  private const val INTEGER_TAG = 0x02
  private const val BIT_STRING_TAG = 0x03
  private const val OCTET_STRING_TAG = 0x04
  private const val NULL_TAG = 0x05
  private const val OBJECT_IDENTIFIER_TAG = 0x06
  private const val UTC_TIME_TAG = 0x17

  /** ASN.1 UTC time format: yyMMddHHmmssZ (2-digit year per X.680) */
  private val UTC_TIME_FORMAT =
      LocalDateTime.Format {
        yearTwoDigits(2000)
        monthNumber()
        day()
        hour()
        minute()
        second()
        char('Z')
      }

  /** Encodes a DER SEQUENCE (tag `0x30`) wrapping the concatenated [values]. */
  fun sequence(vararg values: ByteArray): ByteArray = constructed(SEQUENCE_TAG, values)

  /** Encodes a DER BIT STRING (tag `0x03`): `03 len padBits value...`. */
  fun bitString(padBits: Int, value: ByteArray): ByteArray {
    require(padBits in 0..7) { "Invalid pad bits: $padBits" }
    return Buffer()
        .apply {
          writeByte(BIT_STRING_TAG.toByte())
          writeLength(value.size + 1)
          writeByte(padBits.toByte())
          write(value)
        }
        .readByteArray()
  }

  /** Encodes a DER BOOLEAN TRUE: `[01 01 FF]`. */
  fun booleanTrue(): ByteArray = byteArrayOf(BOOLEAN_TAG.toByte(), 0x01, 0xFF.toByte())

  /** Encodes a DER INTEGER (tag `0x02`) from a Long. */
  fun integer(value: Long): ByteArray = integer(BigInteger.valueOf(value))

  /** Encodes a DER INTEGER (tag `0x02`) from a BigInteger (two's complement, minimal bytes). */
  fun integer(value: BigInteger): ByteArray = tag(INTEGER_TAG, value.toByteArray())

  /** Encodes a DER OCTET STRING (tag `0x04`). */
  fun octetString(value: ByteArray): ByteArray = tag(OCTET_STRING_TAG, value)

  /** Encodes a DER UTC TIME (tag `0x17`) from a raw `yyMMddHHmmssZ` string. */
  fun utcTime(value: String): ByteArray = tag(UTC_TIME_TAG, value.encodeToByteArray())

  /** Encodes a DER UTC TIME (tag `0x17`) from an [Instant], formatted as `yyMMddHHmmssZ`. */
  fun utcTime(value: Instant): ByteArray =
      tag(
          UTC_TIME_TAG,
          value.toLocalDateTime(TimeZone.UTC).format(UTC_TIME_FORMAT).encodeToByteArray(),
      )

  /** Encodes a DER OBJECT IDENTIFIER from a dotted OID string (e.g. "1.2.840.113549.1.1.1"). */
  fun oid(oid: String): ByteArray {
    val parts = oid.split('.').map { it.toInt() }
    require(parts.size >= 2) { "OID requires at least 2 parts" }
    val body =
        Buffer()
            .apply {
              writeByte((parts[0] * 40 + parts[1]).toByte())
              parts.subList(2, parts.size).forEach { writeOidVarint(it) }
            }
            .readByteArray()
    return Buffer()
        .apply {
          writeByte(OBJECT_IDENTIFIER_TAG.toByte())
          writeLength(body.size)
          write(body)
        }
        .readByteArray()
  }

  /** Encodes a DER NULL: `[05 00]`. */
  fun derNull(): ByteArray = byteArrayOf(NULL_TAG.toByte(), 0x00)

  /** Encodes a primitive DER tag (0-31) with the given body. */
  fun tag(tag: Int, body: ByteArray): ByteArray {
    require(tag in 0..31) { "Invalid tag: $tag" }
    return writeTag(tag, body)
  }

  /** Encodes a context-specific implicit tag (class bit 0x80 set). */
  fun contextTag(tag: Int, body: ByteArray): ByteArray {
    require(tag in 0..31) { "Invalid tag: $tag" }
    return writeTag(tag or 0x80, body)
  }

  /** Encodes a context-specific constructed SEQUENCE (class bits 0xA0 set). */
  fun contextSequence(tag: Int, vararg values: ByteArray): ByteArray {
    require(tag in 0..31) { "Invalid tag: $tag" }
    return constructed(tag or 0xA0, values)
  }

  /** Decodes a DER SEQUENCE into its constituent TLV elements (each returned as raw bytes). */
  fun decodeSequence(data: ByteArray): List<ByteArray> {
    require(data[0].toInt() == SEQUENCE_TAG) { "Expected sequence tag" }
    val (dataLength, headerSize) = decodeLengthAt(data, 1)
    val dataStart = 1 + headerSize
    require(dataLength + dataStart == data.size) { "Invalid sequence" }

    return buildList {
      var pos = dataStart
      while (pos < data.size) {
        val elementStart = pos
        pos++ // skip tag
        val (len, lenSize) = decodeLengthAt(data, pos)
        pos += lenSize + len
        add(data.copyOfRange(elementStart, pos))
      }
    }
  }

  /** Unwraps a context-specific optional element (`[A0+n] [len] [inner]`) and returns the inner bytes. */
  fun decodeOptionalElement(element: ByteArray): ByteArray {
    require(element[0].toInt() and 0xE0 == 0xA0) { "Expected optional sequence element tag" }
    val (len, lenSize) = decodeLengthAt(element, 1)
    val dataStart = 1 + lenSize
    require(len + dataStart == element.size) { "Invalid optional sequence element" }
    return element.copyOfRange(dataStart, dataStart + len)
  }

  /**
   * Decodes a DER length at the given offset, returning (length, bytesConsumed).
   *
   * Short form: single byte < 128. Long form: first byte = 0x80 | numBytes, followed by numBytes of
   * big-endian length.
   */
  private fun decodeLengthAt(buffer: ByteArray, offset: Int): Pair<Int, Int> {
    val firstByte = buffer[offset].toInt() and 0xFF
    require(firstByte != 0x80) { "Indefinite lengths not supported in DER" }
    require(firstByte != 0xFF) { "Invalid length first byte 0xFF" }
    if (firstByte < 128) return firstByte to 1

    val numBytes = firstByte and 0x7F
    require(numBytes <= 4) { "Length encoding too large" }
    val length =
        (0 until numBytes).fold(0) { acc, i ->
          (acc shl 8) or (buffer[offset + 1 + i].toInt() and 0xFF)
        }
    return length to (1 + numBytes)
  }

  private fun writeTag(tag: Int, body: ByteArray): ByteArray {
    require(tag in 0..255) { "Invalid tag: $tag" }
    return Buffer()
        .apply {
          writeByte(tag.toByte())
          writeLength(body.size)
          write(body)
        }
        .readByteArray()
  }

  private fun constructed(tag: Int, values: Array<out ByteArray>): ByteArray {
    val totalLength = values.sumOf { it.size }
    return Buffer()
        .apply {
          writeByte(tag.toByte())
          writeLength(totalLength)
          values.forEach { write(it) }
        }
        .readByteArray()
  }

  /**
   * Writes a DER length encoding to this buffer.
   *
   * ```
   * writeLength(5)   → [0x05]                 (short form)
   * writeLength(200) → [0x81, 0xC8]           (1 length byte)
   * writeLength(256) → [0x82, 0x01, 0x00]     (2 length bytes)
   * ```
   */
  private fun Buffer.writeLength(length: Int) {
    if (length < 128) {
      writeByte(length.toByte())
    } else {
      val numBits = 32 - length.countLeadingZeroBits()
      val numBytes = (numBits + 7) / 8
      writeByte((numBytes or 0x80).toByte())
      for (i in numBytes - 1 downTo 0) {
        writeByte((length ushr (i * 8)).toByte())
      }
    }
  }

  /**
   * Writes an OID arc as a base-128 varint. High bit = more bytes follow.
   *
   * ```
   * writeOidVarint(113549) → [0x86, 0xF7, 0x0D]  (3 bytes, base-128)
   * writeOidVarint(2)      → [0x02]               (single byte)
   * ```
   */
  private fun Buffer.writeOidVarint(number: Int) {
    if (number < 128) {
      writeByte(number.toByte())
    } else {
      val numBits = Int.SIZE_BITS - number.countLeadingZeroBits()
      val numParts = (numBits + 6) / 7
      for (i in numParts - 1 downTo 1) {
        writeByte(((number ushr (i * 7)) and 0x7F or 0x80).toByte())
      }
      writeByte((number and 0x7F).toByte())
    }
  }
}
