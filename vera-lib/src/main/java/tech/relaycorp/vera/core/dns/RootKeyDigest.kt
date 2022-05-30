package tech.relaycorp.vera.core.dns

import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import tech.relaycorp.vera.crypto.getSHA256Digest

data class RootKeyDigest(val rsaModulus: Int, val digestBase64: String) {
    val txtValue get() = "rsa-${rsaModulus} sha256:${digestBase64}"

    companion object {
        fun initFromPublicKey(publicKey: PublicKey): RootKeyDigest {
            val digest = getSHA256Digest(publicKey.encoded)
            val digestBase64 = Base64.getEncoder().encodeToString(digest)
            publicKey  as RSAPublicKey
            return RootKeyDigest(publicKey.modulus.bitLength(), digestBase64)
        }
    }
}
