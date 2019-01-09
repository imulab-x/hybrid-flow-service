plugins {
    idea
    java
    application
    kotlin("jvm") version "1.3.10"
    id("com.github.johnrengelman.shadow") version "4.0.2"
    id("com.gradle.build-scan") version "2.1"
}

group = "io.imulab.x"
version = "0.1.0"

buildScan {
    termsOfServiceUrl = "https://gradle.com/terms-of-service"
    termsOfServiceAgree = "yes"
    publishAlways()
}

application {
    // Define the main class for the application
    mainClassName = "io.imulab.astrea.service.flow.hybrid.AppKt"
}

repositories {
    maven(url = "https://artifactory.imulab.io/artifactory/gradle-dev-local/")
    jcenter()
    mavenCentral()
}

tasks {
    compileKotlin {
        sourceCompatibility = "1.8"
        targetCompatibility = "1.8"
        kotlinOptions {
            jvmTarget = "1.8"
            suppressWarnings = true
            freeCompilerArgs = listOf()
        }
    }
    compileTestKotlin {
        sourceCompatibility = "1.8"
        targetCompatibility = "1.8"
        kotlinOptions {
            jvmTarget = "1.8"
            suppressWarnings = true
            freeCompilerArgs = listOf()
        }
    }
    test {
        useJUnitPlatform()
        systemProperties = System.getProperties().map { it.key.toString() to it.value }.toMap()
    }
    shadowJar {
        classifier = ""
        mergeServiceFiles {
            include("META-INF/services/io.vertx.core.spi.VerticleFactory")
        }
    }
}

dependencies {
    implementation(platform("io.imulab.x:astrea-dependencies:7"))
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")
    implementation("io.imulab.x:astrea-commons:0.4.0")
    implementation("io.grpc:grpc-netty")
    implementation("io.vertx:vertx-core")
    implementation("io.vertx:vertx-lang-kotlin")
    implementation("io.vertx:vertx-web")
    implementation("io.vertx:vertx-grpc")
    implementation("io.vertx:vertx-health-check")
    implementation("io.vertx:vertx-zookeeper")
    implementation("io.vertx:vertx-redis-client")
    implementation("org.kodein.di:kodein-di-generic-jvm")
    implementation("com.typesafe:config")
    implementation("com.squareup.okhttp3:okhttp")
    implementation("io.github.resilience4j:resilience4j-retry")
    implementation("org.slf4j:slf4j-api")
    runtimeOnly("org.apache.logging.log4j:log4j-api")
    runtimeOnly("org.apache.logging.log4j:log4j-core")
    runtimeOnly("org.apache.logging.log4j:log4j-slf4j-impl")

    testImplementation("io.kotlintest:kotlintest-runner-junit5")
    testImplementation("com.nhaarman.mockitokotlin2:mockito-kotlin")
    testImplementation("org.skyscreamer:jsonassert:1.5.0")
}

