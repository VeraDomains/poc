package tech.relaycorp.vera.app.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import java.io.File
import tech.relaycorp.vera.core.MemberIdBundle
import tech.relaycorp.vera.core.VeraSignatureBundle
import tech.relaycorp.vera.crypto.deserializeRSAKeyPair

class Sign : CliktCommand("Sign plaintext") {
    private val memberPrivateKeyPath by argument()
    private val memberIdBundlePath by argument()

    override fun run() {
        val plaintext = readStdin("Plaintext should be passed via stdin")
        val memberKeyPair = File(memberPrivateKeyPath).readBytes().deserializeRSAKeyPair()
        val memberIdBundle = MemberIdBundle.deserialize(File(memberIdBundlePath).readBytes())
        val signatureBundle = VeraSignatureBundle.sign(
            plaintext,
            memberKeyPair.private,
            memberIdBundle,
        )
        System.out.write(signatureBundle.serialize())
    }
}
