package tech.relaycorp.vera.ca.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands

class MainCommand : CliktCommand(name = "vera-server") {
    override fun run() = Unit
}

fun main(args: Array<String>) = MainCommand()
    .subcommands(KeyGen(), GenerateRootCA(), GetVeraTXT())
    .main(args)
