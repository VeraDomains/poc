package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands

class MainCommand : CliktCommand(name = "vera-ca") {
    override fun run() = Unit
}

fun main(args: Array<String>) = MainCommand()
    .subcommands(KeyGen(), GenerateRootCA(), GetDnssecChain(), IssueMemberId())
    .main(args)
