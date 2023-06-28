// dummy required by 'shadowJar' task
project.setProperty("mainClassName", "com.dummy.MainClass")

plugins {
    kotlin("jvm") version "1.8.0"
    id("io.ktor.plugin") version "2.3.1"
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

    implementation("com.github.mattrglobal:bbs.signatures:1.6-SNAPSHOT")
    implementation("com.apicatalog:titanium-json-ld-jre8:1.3.2")
    implementation("org.glassfish:jakarta.json:2.0.1")
    implementation("io.setl:rdf-urdna:1.2")
    implementation("io.github.novacrypto:Base58:2022.01.17")

    implementation("io.ktor:ktor-server-core")
    implementation("io.ktor:ktor-server-cio")
    implementation("io.ktor:ktor-server-websockets")
    implementation("io.ktor:ktor-client-core")
    implementation("io.ktor:ktor-client-cio")
    implementation("io.ktor:ktor-client-websockets")
    implementation("io.ktor:ktor-serialization-kotlinx-json")

    testImplementation("org.junit.platform:junit-platform-suite-engine:1.9.1")
    testImplementation(kotlin("test"))

    implementation("io.github.microutils:kotlin-logging-jvm:3.0.5")
    testImplementation("ch.qos.logback:logback-classic:1.4.8")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}
