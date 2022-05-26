package tech.relaycorp.vera.crypto.x509

import tech.relaycorp.vera.crypto.CryptoException

class CertificateException(message: String, cause: Throwable? = null) :
    CryptoException(message, cause)
