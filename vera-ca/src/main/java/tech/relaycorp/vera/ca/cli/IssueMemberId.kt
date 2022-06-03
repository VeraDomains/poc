package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import java.io.File
import java.time.ZonedDateTime
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration
import tech.relaycorp.vera.core.MemberIdBundle
import tech.relaycorp.vera.core.dns.RootCAChain
import tech.relaycorp.vera.core.pki.issueMemberCertificate
import tech.relaycorp.vera.crypto.deserializeRSAKeyPair
import tech.relaycorp.vera.crypto.deserializeRSAPublicKey
import tech.relaycorp.vera.crypto.x509.Certificate

class IssueMemberId : CliktCommand("Issue a member id bundle") {
    private val userName by option(help = "The user name, unless the member is a bot")

    private val dnssecChainPath by argument()
    private val caPrivateKeyPath by argument()
    private val caCertificatePath by argument()
    private val serviceId by argument()
    private val ttl by option().convert { Duration.parse(it) }.default(30.days)

    override fun run() {
        val caKeyPair = File(caPrivateKeyPath).readBytes().deserializeRSAKeyPair()
        val caCertificate = Certificate.deserialize(File(caCertificatePath).readBytes())

        val memberCertificateExpiryDate = ZonedDateTime.now().plus(ttl.toJavaDuration())
        val memberPublicKey = readStdin("Member public key should be passed via stdin")
            .deserializeRSAPublicKey()

        val memberCertificate = issueMemberCertificate(
            userName,
            memberPublicKey,
            caKeyPair.private,
            caCertificate,
            memberCertificateExpiryDate,
            serviceId,
        )
        val dnssecChain = RootCAChain.deserialize(File(dnssecChainPath).readBytes())
        val bundle = MemberIdBundle(memberCertificate, caCertificate, dnssecChain)
        System.out.write(bundle.serialise())
    }

}
