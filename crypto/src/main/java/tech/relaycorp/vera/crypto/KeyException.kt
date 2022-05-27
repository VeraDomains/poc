package tech.relaycorp.vera.crypto

/**
 * Exception while generating a cryptographic key.
 */
class KeyException(message: String, cause: Throwable? = null) : CryptoException(message, cause)
