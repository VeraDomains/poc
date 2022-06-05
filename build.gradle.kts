plugins {
    id("myproject.java-conventions")
}

tasks.named("build") {
    finalizedBy(":vera-ca:installDist")
    finalizedBy(":vera-app:installDist")
}
