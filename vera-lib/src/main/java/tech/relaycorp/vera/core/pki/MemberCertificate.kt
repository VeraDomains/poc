package tech.relaycorp.vera.core.pki

import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import tech.relaycorp.vera.crypto.x509.Certificate

fun issueMemberCertificate(
    userName: String?,
    memberPublicKey: PublicKey,
    caPrivateKey: PrivateKey,
    caCertificate: Certificate,
    expiryDate: ZonedDateTime,
    serviceId: String,
): Certificate {
    val serviceOID = ASN1ObjectIdentifier(serviceId)
    val additionalExtensions = listOf(
        VeraIdExtension(serviceOID),
    )
    return Certificate.issue(
        userName ?: "",
        memberPublicKey,
        caPrivateKey,
        expiryDate,
        caCertificate,
        isCA = false,
        pathLenConstraint = 0,
        additionalExtensions = additionalExtensions,
    )
}
