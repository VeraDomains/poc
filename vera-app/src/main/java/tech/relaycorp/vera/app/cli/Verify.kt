package tech.relaycorp.vera.app.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration
import tech.relaycorp.vera.core.MemberIdBundle
import tech.relaycorp.vera.core.SignatureVerificationException
import tech.relaycorp.vera.core.VeraSignatureBundle

class Verify : CliktCommand("Verify plaintext") {
    private val signaturePath by argument()
    private val serviceId by argument()
    private val ttl by option().convert { Duration.parse(it) }.default(7.days)

    override fun run() {
        val plaintext = readStdin("Plaintext should be passed via stdin")
        val signatureBundle =
            VeraSignatureBundle.deserialize(File(signaturePath).readBytes())

        try {
            signatureBundle.verify(plaintext, serviceId, ttl.toJavaDuration())
        } catch (exc: SignatureVerificationException) {
            echo("The signature is invalid", err = true)
            echo("Reason: ${exc.message}", err = true)
            echo()
            echoSignatureInfo(signatureBundle.memberIdBundle)
            throw ProgramResult(1)
        }

        echo("The signature is valid!")
        echoSignatureInfo(signatureBundle.memberIdBundle)
    }

    private fun echoSignatureInfo(memberIdBundle: MemberIdBundle) {
        echo("Signer: ${memberIdBundle.id}")
        echo("Service: $serviceId")
    }
}
