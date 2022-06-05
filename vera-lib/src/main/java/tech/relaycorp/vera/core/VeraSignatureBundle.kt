package tech.relaycorp.vera.core

import java.security.PrivateKey
import java.time.Duration
import java.time.ZonedDateTime
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.cms.SignedData
import tech.relaycorp.vera.crypto.cms.SignedDataException

class VeraSignatureBundle(
    private val signature: SignedData,
    val memberIdBundle: MemberIdBundle,
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

    @Throws(SignatureVerificationException::class)
    fun verify(plaintext: ByteArray, serviceId: String, ttl: Duration) {
        memberIdBundle.verify(ASN1ObjectIdentifier(serviceId))

        try {
            signature.verify(plaintext, memberIdBundle.memberCertificate)
        } catch (exc: SignedDataException) {
            throw SignatureVerificationException("Signature is invalid", exc)
        }

        val now = ZonedDateTime.now()
        val earliestStartDate = now.minus(ttl)
        if (memberIdBundle.expiryDate < now) {
            throw SignatureVerificationException("Member Id expired on $now")
        }
        if (memberIdBundle.startDate < earliestStartDate) {
            throw SignatureVerificationException(
                "Member Id is too old (it's been valid since ${memberIdBundle.startDate})"
            )
        }
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
