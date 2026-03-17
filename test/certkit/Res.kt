package certkit

import java.nio.file.Path
import kotlin.io.path.toPath

/** Resolves a test resource [name] to a [Path]. */
fun resPath(name: String): Path =
    Thread.currentThread().contextClassLoader.getResource(name)?.toURI()?.toPath()
        ?: error("Resource not found: $name")

/** Reads a test resource [name] as a [ByteArray]. */
fun resBytes(name: String): ByteArray =
    Thread.currentThread().contextClassLoader.getResourceAsStream(name)?.readAllBytes()
        ?: error("Resource not found: $name")

/** Reads a test resource [name] as a UTF-8 [String]. */
fun resText(name: String): String = resBytes(name).decodeToString()
