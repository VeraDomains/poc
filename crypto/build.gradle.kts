plugins {
    id("myproject.java-conventions")
}

dependencies {
    val bouncyCastleVersion = "1.70"
    implementation("org.bouncycastle:bcprov-jdk15on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk15on:$bouncyCastleVersion")
}
