package tech.relaycorp.vera.core

import java.time.ZonedDateTime
import java.util.Base64
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.vera.core.dns.RootCAChain
import tech.relaycorp.vera.core.pki.VeraIdExtension
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.crypto.getSHA256Digest
import tech.relaycorp.vera.crypto.x509.Certificate
import tech.relaycorp.vera.crypto.x509.CertificateException

class MemberIdBundle(
    val memberCertificate: Certificate,
    private val organisationCertificate: Certificate,
    private val rootCAChain: RootCAChain,
) {
    val startDate
        get(): ZonedDateTime = maxOf(
            rootCAChain.startDate,
            organisationCertificate.startDate,
            memberCertificate.startDate,
        )
    val expiryDate
        get(): ZonedDateTime = minOf(
            rootCAChain.expiryDate,
            organisationCertificate.expiryDate,
            memberCertificate.expiryDate,
        )

    val id
        get(): String = if (memberCertificate.commonName.isEmpty())
            memberCertificate.issuerCommonName
        else
            "${memberCertificate.commonName}@${memberCertificate.issuerCommonName}"

    fun serialise(): ByteArray {
        val sequence = ASN1Utils.makeSequence(
            listOf(
                DEROctetString(memberCertificate.serialize()),
                DEROctetString(organisationCertificate.serialize()),
                DEROctetString(rootCAChain.serialise()),
            ),
            false,
        )
        return sequence.encoded
    }

    @Throws(SignatureVerificationException::class)
    fun verify(serviceId: ASN1ObjectIdentifier) {
        rootCAChain.verify()

        validateOrganisationCertificate()
        validateMemberCertificate(serviceId)
    }

    @Throws(SignatureVerificationException::class)
    private fun validateOrganisationCertificate() {
        try {
            organisationCertificate.validate()
        } catch (exc: CertificateException) {
            throw SignatureVerificationException(
                "Organisation certificate is invalid",
                exc,
            )
        }

        validateCAName()
        validateCAPublicKey()
        validateCADateRange()
    }

    @Throws(SignatureVerificationException::class)
    private fun validateCAName() {
        if (organisationCertificate.commonName != rootCAChain.domainName) {
            throw SignatureVerificationException(
                "Root CA common name (${organisationCertificate.commonName}) does not " +
                    "match domain name in DNSSEC chain (${rootCAChain.domainName})",
            )
        }
    }

    @Throws(SignatureVerificationException::class)
    private fun validateCAPublicKey() {
        val expectedDigest = getSHA256Digest(organisationCertificate.subjectPublicKey.encoded)
        val expectedDigestBase64 = Base64.getEncoder().encodeToString(expectedDigest)
        val expectedSpec = "rsa2048-sha256:$expectedDigestBase64"
        if (rootCAChain.publicKeySpec != expectedSpec) {
            throw SignatureVerificationException(
                "Vera CA key does not match TXT record"
            )
        }
    }

    @Throws(SignatureVerificationException::class)
    private fun validateCADateRange() {
        if (organisationCertificate.expiryDate < rootCAChain.startDate) {
            throw SignatureVerificationException(
                "Vera CA expires before DNSSEC validity begins"
            )
        }
        if (rootCAChain.expiryDate < organisationCertificate.startDate) {
            throw SignatureVerificationException(
                "DNSSEC chain expires before Vera CA validity begins"
            )
        }
    }

    @Throws(SignatureVerificationException::class)
    private fun validateMemberCertificate(serviceId: ASN1ObjectIdentifier) {
        try {
            memberCertificate.validate()
        } catch (exc: CertificateException) {
            throw SignatureVerificationException(
                "Member certificate is invalid", exc,
            )
        }
        try {
            memberCertificate.getCertificationPath(emptyList(), listOf(organisationCertificate))
        } catch (exc: CertificateException) {
            throw SignatureVerificationException(
                "Member certificate was not issued by Vera CA (${exc.message})"
            )
        }

        val veraIdExtensionRaw = memberCertificate.extensions.single {
            it.oid == VeraIdExtension.OID
        }
        val veraIdExtension = VeraIdExtension.deserialize(veraIdExtensionRaw.getValue())
        val authorizedServicedId = veraIdExtension.serviceId
        if (serviceId != authorizedServicedId) {
            throw SignatureVerificationException(
                "Member certificate is valid in a different service " +
                    "(${serviceId.id}, not ${authorizedServicedId.id})"
            )
        }
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
