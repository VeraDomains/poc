package tech.relaycorp.vera.core.pki

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.vera.core.OIDs
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.x509.CertificateExtension

internal class VeraIdExtension(private val serviceId: ASN1ObjectIdentifier) : CertificateExtension(
    OID,
    true,
) {
    override fun getValue(): ASN1Encodable =
        ASN1Utils.makeSequence(listOf(serviceId), false)

    companion object {
        private val OID = OIDs.VERA.branch("0").intern()
    }
}
