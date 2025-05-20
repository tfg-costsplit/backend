import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    kotlin("jvm")
    application
    id("com.google.cloud.tools.appengine") version "2.8.3"
    id("com.gradleup.shadow") version "9.0.0-beta13"
}

group = "io.github.costsplit"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.org.slf4j.slf4j.simple)
    implementation(libs.com.zaxxer.hikaricp)
    implementation(libs.org.postgresql.postgresql)
    implementation(project(":app"))
    implementation(libs.org.jetbrains.exposed.exposed.jdbc)
    implementation("com.google.cloud:google-cloud-core:2.53.1")
    implementation("com.google.cloud:google-cloud-secretmanager:2.60.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "MainKt"
}

tasks.named<ShadowJar>("shadowJar") {
    mergeServiceFiles()
}

appengine {
    stage {
        setArtifact(layout.buildDirectory.file("libs/release-env-all.jar").get().asFile)
    }
    deploy {
        projectId = "costsplit-456211"
        version = "test-1"
    }
}

