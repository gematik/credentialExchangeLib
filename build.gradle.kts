plugins {
    kotlin("jvm") version "1.8.0"
    kotlin("plugin.serialization") version "1.8.21"
    `maven-publish`
    `java-library`
}

group = "de.gematik"
version = "1.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.8.20-RC")
    implementation("org.jetbrains.kotlinx:kotlinx-datetime-jvm:0.4.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.0")

    implementation("org.json:json:20230227")

    implementation("decentralized-identity:jsonld-common-java:1.2-SNAPSHOT")

    testImplementation("org.jetbrains.kotlin:kotlin-test:1.8.20-RC")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}
