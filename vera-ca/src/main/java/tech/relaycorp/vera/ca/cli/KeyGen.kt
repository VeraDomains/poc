package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import java.io.File
import tech.relaycorp.vera.core.dns.RootCARecord
import tech.relaycorp.vera.core.dns.RootKeyDigest
import tech.relaycorp.vera.crypto.generateRSAKeyPair

class KeyGen : CliktCommand("Create a new key pair") {
    private val domain by argument()
    private val privateKeyOutputPath by argument()

    override fun run() {
        val keyPair = generateRSAKeyPair()

        val privateKeyFile = File(privateKeyOutputPath)
        privateKeyFile.writeBytes(keyPair.private.encoded)
        echo("Private key written to $privateKeyOutputPath")
        echo()

        val publicKeyDigest = RootKeyDigest.initFromPublicKey(keyPair.public)
        val caRecord = RootCARecord(domain, publicKeyDigest)
        echo("Create the following TXT record under ${domain}:")
        echo(caRecord.txtRecord)
    }
}
