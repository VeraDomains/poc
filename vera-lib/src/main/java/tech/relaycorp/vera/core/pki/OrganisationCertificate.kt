package tech.relaycorp.vera.core.pki

import java.security.KeyPair
import java.time.ZonedDateTime
import kotlin.time.Duration
import kotlin.time.toJavaDuration
import tech.relaycorp.vera.crypto.x509.Certificate

fun issueOrganisationCertificate(
    domain: String,
    keyPair: KeyPair,
    ttl: Duration,
): Certificate {
    val now = ZonedDateTime.now()
    return Certificate.issue(
        domain,
        keyPair.public,
        keyPair.private,
        now.plus(ttl.toJavaDuration()),
        isCA = true,
        pathLenConstraint = 1,
    )
}
