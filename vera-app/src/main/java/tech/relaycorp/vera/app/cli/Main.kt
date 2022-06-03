package tech.relaycorp.vera.app.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands

class MainCommand : CliktCommand(name = "vera-app") {
    override fun run() = Unit
}

fun main(args: Array<String>) = MainCommand()
    .subcommands(Sign())
    .main(args)
