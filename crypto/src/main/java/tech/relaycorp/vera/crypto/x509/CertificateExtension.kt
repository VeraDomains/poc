package tech.relaycorp.vera.crypto.x509

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier

abstract class CertificateExtension(
    internal val oid: ASN1ObjectIdentifier,
    internal val isCritical: Boolean
) {
    abstract fun getValue(): ASN1Encodable
}
