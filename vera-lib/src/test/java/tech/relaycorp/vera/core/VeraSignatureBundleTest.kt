package tech.relaycorp.vera.core

import java.time.ZonedDateTime
import kotlin.time.Duration.Companion.days
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import tech.relaycorp.vera.core.dns.RootCAChain
import tech.relaycorp.vera.core.pki.issueMemberCertificate
import tech.relaycorp.vera.core.pki.issueOrganisationCertificate
import tech.relaycorp.vera.crypto.generateRSAKeyPair

class VeraSignatureBundleTest {
    private val domainName = "chores.fans"
    private val plaintext = "the plaintext".toByteArray()
    private val orgKeyPair = generateRSAKeyPair()
    private val orgCertificate = issueOrganisationCertificate(
        domainName,
        orgKeyPair,
        1.days
    )
    private val memberKeyPair = generateRSAKeyPair()
    private val memberCertificate = issueMemberCertificate(
        null,
        memberKeyPair.public,
        orgKeyPair.private,
        orgCertificate,
        ZonedDateTime.now().plusDays(1),
        "1.2.3.4",
    )

    @Test
    fun identity() = runBlocking {
        val chain = RootCAChain.retrieve(domainName)
        val memberIdBundle = MemberIdBundle(
            memberCertificate,
            orgCertificate,
            chain
        )
        val bundle = VeraSignatureBundle.sign(plaintext, memberKeyPair.private, memberIdBundle)
        val bundleSerialized = bundle.serialize()

        val bundleDeserialized = VeraSignatureBundle.deserialize(bundleSerialized)

        assertArrayEquals(bundleSerialized, bundleDeserialized.serialize())
    }
}