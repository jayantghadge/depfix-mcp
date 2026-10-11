plugins { java }

extra["jjwtVersion"] = "0.12.6"

dependencies {
    implementation("io.jsonwebtoken:jjwt-api:${jjwtVersion}")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}
