plugins {
    id("myproject.java-conventions")
    application
}

dependencies {
    implementation("com.github.ajalt.clikt:clikt:3.4.2")
    implementation(project(":vera-lib"))
}

application {
    mainClass.set("tech.relaycorp.vera.app.cli.MainKt")
}
