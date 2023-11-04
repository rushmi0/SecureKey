plugins {
    kotlin("jvm") version "1.9.20"
    application
}

group = "org.securekey"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {

    testImplementation(kotlin("test"))

    // https://mvnrepository.com/artifact/com.google.guava/guava
    implementation("com.google.guava:guava:32.1.2-jre")

    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.11.0")

    // https://mvnrepository.com/artifact/fr.acinq.secp256k1/secp256k1-kmp-jni-jvm
    runtimeOnly("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.11.0")


}

tasks.test {
    useJUnitPlatform()
}

tasks {

    compileTestKotlin {
        kotlinOptions {
            jvmTarget = "17"
        }
    }

    compileKotlin {
        kotlinOptions {
            jvmTarget = "17"
        }
    }

}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("MainKt")
}