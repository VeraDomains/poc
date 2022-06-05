package tech.relaycorp.vera.core.pki

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.vera.core.OIDs
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.x509.CertificateExtension

class VeraIdExtension(val serviceId: ASN1ObjectIdentifier) : CertificateExtension(
    OID,
    false, // Should be critical, but we'd have to get the BC path checker to ignore it
) {
    override fun getValue(): ASN1Encodable =
        ASN1Utils.makeSequence(listOf(serviceId), false)

    companion object {
        val OID: ASN1ObjectIdentifier = OIDs.VERA.branch("0").intern()

        fun deserialize(serialization: ASN1Encodable): VeraIdExtension {
            val extensionValue = DEROctetString.getInstance(serialization)
            val sequence = ASN1Utils.deserializeHeterogeneousSequence(extensionValue.octets)
            val oid = ASN1ObjectIdentifier.getInstance(sequence.first(), false)
            return VeraIdExtension(oid)
        }
    }
}
