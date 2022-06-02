plugins {
    id("myproject.java-conventions")
}

dependencies {
    api(project(":crypto"))
    implementation("com.github.gnarea:dnsjava:public-dnssec-validation-SNAPSHOT")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")

    testImplementation("org.junit.jupiter:junit-jupiter:5.8.1")
}
