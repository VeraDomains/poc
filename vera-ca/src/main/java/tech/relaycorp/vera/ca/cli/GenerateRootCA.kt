package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.long
import java.time.ZonedDateTime
import tech.relaycorp.vera.crypto.deserializeRSAKeyPair
import tech.relaycorp.vera.crypto.x509.Certificate

class GenerateRootCA : CliktCommand("Create a new root CA certificate") {
    private val domain by argument()
    private val ttlDays by option().long().default(90)

    override fun run() {
        val privateKeySerialized = readStdin("Private key should be passed via stdin")
        val keyPair = privateKeySerialized.deserializeRSAKeyPair()
        val now = ZonedDateTime.now()
        val certificate = Certificate.issue(
            domain,
            keyPair.public,
            keyPair.private,
            now.plusDays(ttlDays),
            isCA = true,
            pathLenConstraint = 1,
        )
        System.out.write(certificate.serialize())
    }
}
