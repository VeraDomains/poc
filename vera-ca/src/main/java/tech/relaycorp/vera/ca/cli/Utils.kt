package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.InvalidFileFormat

internal fun readStdin(errorMessage: String): ByteArray {
    if (System.`in`.available() == 0) {
        throw InvalidFileFormat("stdin", errorMessage)
    }
    return System.`in`.readBytes()
}
