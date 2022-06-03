package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import tech.relaycorp.vera.core.dns.RootCAChain

class GetDnssecChain : CliktCommand("Retrieve the Vera TXT record") {
    private val domain by argument()

    override fun run() {
        runBlocking {
            val chain = RootCAChain.retrieve(domain)
            val chainSerialised = chain.serialise()
            withContext(Dispatchers.IO) {
                System.out.write(chainSerialised)
            }
        }
    }
}
