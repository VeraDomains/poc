package tech.relaycorp.vera.core.dns

import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import tech.relaycorp.vera.crypto.getSHA256DigestHex

data class RootKeyDigest(val rsaModulus: Int, val digestHex: String) {
    val txtValue get() = "rsa-${rsaModulus} sha256-hex:${digestHex}"

    companion object {
        fun initFromPublicKey(publicKey: PublicKey): RootKeyDigest {
            val digest = getSHA256DigestHex(publicKey.encoded)
            publicKey  as RSAPublicKey
            return RootKeyDigest(publicKey.modulus.bitLength(), digest)
        }
    }
}
