plugins {
    kotlin("jvm") version "1.8.0"
    kotlin("plugin.serialization") version "1.8.21"
    `maven-publish`
    `java-library`
}

group = "de.gematik"
version = "0.3.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
    maven("https://maven.scijava.org/content/repositories/public/")
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.8.20-RC")
    implementation("org.jetbrains.kotlinx:kotlinx-datetime-jvm:0.4.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.0")

    // implementation("com.github.mattrglobal:bbs.signatures:1.6-SNAPSHOT")
    implementation(fileTree("libs") { include("*.jar") })
    api("com.apicatalog:titanium-json-ld-jre8:1.3.2")
    api("org.glassfish:jakarta.json:2.0.1")
    api("io.setl:rdf-urdna:1.2")
    api("io.github.novacrypto:Base58:2022.01.17")

    api("io.ktor:ktor-server-core:2.3.1")
    api("io.ktor:ktor-server-cio:2.3.1")
    api("io.ktor:ktor-server-websockets:2.3.1")
    implementation("io.ktor:ktor-client-core:2.3.1")
    implementation("io.ktor:ktor-client-cio:2.3.1")
    implementation("io.ktor:ktor-client-websockets:2.3.1")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.1")

    implementation ("org.didcommx:didcomm:0.3.3-SNAPSHOT")
    implementation ("org.didcommx:peerdid:0.5.0")


    testImplementation("org.junit.platform:junit-platform-suite-engine:1.9.1")
    testImplementation(kotlin("test"))

    implementation("io.github.microutils:kotlin-logging-jvm:3.0.5")
    implementation("ch.qos.logback:logback-classic:1.3.8")

    implementation ("org.bouncycastle:bcprov-jdk18on:1.76")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}

java {
//    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}
