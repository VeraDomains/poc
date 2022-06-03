package tech.relaycorp.vera.core

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.vera.core.dns.RootCAChain
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.x509.Certificate

class MemberIdBundle(
    val memberCertificate: Certificate,
    private val organisationCertificate: Certificate,
    private val dnssecChain: RootCAChain,
) {
    fun serialise(): ByteArray {
        val sequence = ASN1Utils.makeSequence(
            listOf(
                DEROctetString(memberCertificate.serialize()),
                DEROctetString(organisationCertificate.serialize()),
                DEROctetString(dnssecChain.serialise()),
            ),
            false,
        )
        return sequence.encoded
    }

    companion object {
        fun deserialize(serialization: ByteArray): MemberIdBundle {
            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val memberCertificate =
                Certificate.deserialize(ASN1Utils.getOctetString(sequence.first()).octets)
            val organisationCertificate =
                Certificate.deserialize(ASN1Utils.getOctetString(sequence[1]).octets)
            val dnssecChain =
                RootCAChain.deserialize(ASN1Utils.getOctetString(sequence.last()).octets)
            return MemberIdBundle(memberCertificate, organisationCertificate, dnssecChain)
        }
    }
}
