package tech.relaycorp.vera.crypto.cms

import tech.relaycorp.vera.crypto.CryptoException

class SignedDataException(message: String, cause: Throwable? = null) :
    CryptoException(message, cause)
