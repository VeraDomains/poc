package tech.relaycorp.vera.crypto.x509

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier

class RawCertificateExtension(
    oid: ASN1ObjectIdentifier,
    isCritical: Boolean,
    private val rawValue: ASN1Encodable,
) : CertificateExtension(oid, isCritical) {
    override fun getValue() = rawValue
}
