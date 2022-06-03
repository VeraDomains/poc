package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import tech.relaycorp.vera.core.pki.issueOrganisationCertificate
import tech.relaycorp.vera.crypto.deserializeRSAKeyPair

class GenerateRootCA : CliktCommand("Create a new root CA certificate") {
    private val domain by argument()
    private val ttl by option().convert { Duration.parse(it) }.default(90.days)

    override fun run() {
        val privateKeySerialized = readStdin("Private key should be passed via stdin")
        val keyPair = privateKeySerialized.deserializeRSAKeyPair()
        val certificate = issueOrganisationCertificate(
            domain,
            keyPair,
            ttl
        )
        System.out.write(certificate.serialize())
    }
}
