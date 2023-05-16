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

    implementation("com.github.mattrglobal:bbs.signatures:1.6-SNAPSHOT")
    implementation("com.apicatalog:titanium-json-ld-jre8:1.3.2")
    implementation("org.glassfish:jakarta.json:2.0.1")
    implementation("io.setl:rdf-urdna:1.2")
    implementation("io.github.novacrypto:Base58:2022.01.17")

    testImplementation("org.junit.platform:junit-platform-suite-engine:1.9.1")
    testImplementation("org.jetbrains.kotlin:kotlin-test:1.8.20-RC")
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
