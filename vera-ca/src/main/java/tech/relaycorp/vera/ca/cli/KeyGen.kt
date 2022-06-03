package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import tech.relaycorp.vera.core.dns.RootKeyDigest
import tech.relaycorp.vera.crypto.generateRSAKeyPair

class KeyGen : CliktCommand("Create a new key pair") {
    private val domain by argument()
    private val privateKeyOutputPath by argument()
    private val ttl by option().convert { Duration.parse(it) }.default(90.days)

    override fun run() {
        val keyPair = generateRSAKeyPair()

        val privateKeyFile = File(privateKeyOutputPath)
        privateKeyFile.writeBytes(keyPair.private.encoded)
        echo("Private key written to $privateKeyOutputPath")
        echo()

        val publicKeyDigest = RootKeyDigest.initFromPublicKey(keyPair.public)
        echo("Create the following TXT record under ${domain}:")
        val ttlSeconds = ttl.inWholeSeconds
        echo("_vera.${domain}. IN TXT \"${publicKeyDigest.txtValue} $ttlSeconds\"")
    }
}
