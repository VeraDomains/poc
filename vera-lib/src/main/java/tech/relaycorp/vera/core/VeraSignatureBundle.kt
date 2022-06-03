package tech.relaycorp.vera.core

import java.security.PrivateKey
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.cms.SignedData

class VeraSignatureBundle(
    private val signature: SignedData,
    private val memberIdBundle: MemberIdBundle,
) {
    fun serialize(): ByteArray {
        val sequence = ASN1Utils.makeSequence(
            listOf(
                DEROctetString(signature.serialize()),
                DEROctetString(memberIdBundle.serialise()),
            ),
            false,
        )
        return sequence.encoded
    }

    companion object {
        fun sign(
            plaintext: ByteArray,
            signerPrivateKey: PrivateKey,
            memberIdBundle: MemberIdBundle
        ): VeraSignatureBundle {
            val signature = SignedData.sign(
                plaintext,
                signerPrivateKey,
                memberIdBundle.memberCertificate,
                encapsulatePlaintext = false,
            )
            return VeraSignatureBundle(signature, memberIdBundle)
        }

        fun deserialize(serialization: ByteArray): VeraSignatureBundle {
            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val signature = SignedData.deserialize(ASN1Utils.getOctetString(sequence.first()).octets)
            val memberIdBundle = MemberIdBundle.deserialize(ASN1Utils.getOctetString(sequence.last()).octets)
            return VeraSignatureBundle(signature, memberIdBundle)
        }
    }
}