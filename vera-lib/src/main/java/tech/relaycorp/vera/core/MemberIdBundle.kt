package tech.relaycorp.vera.core

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.vera.core.dns.RootCAChain
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.x509.Certificate

class MemberIdBundle(
    private val memberCertificate: Certificate,
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
}
