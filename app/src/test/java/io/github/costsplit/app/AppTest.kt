package io.github.costsplit.app

import com.dumbster.smtp.SimpleSmtpServer
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.h2.Driver
import org.jetbrains.exposed.sql.Database
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AppTest {
    private lateinit var dumbster: SimpleSmtpServer
    private lateinit var dataSource: HikariDataSource
    private lateinit var app: App

    @BeforeEach
    fun setUp() {
        dumbster = SimpleSmtpServer.start(SimpleSmtpServer.AUTO_SMTP_PORT)
        dataSource = HikariDataSource(
            HikariConfig().apply {
                jdbcUrl = "jdbc:h2:mem:test"
                driverClassName = Driver::class.qualifiedName
            }
        )
        app = App(
            database = Database.connect(datasource = dataSource),
            secret = "1234",
            senderMail = "sender@test.net",
            senderPassword = "1234",
            smtpHost = "localhost",
            smtpPort = dumbster.port,
            saltSecret = "x".repeat(16).toByteArray(),
        )
    }

    @AfterEach
    fun tearDown() {
        app.close()
        dataSource.close()
        dumbster.close()
    }

    @Test
    fun `POST to create user succeeds`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "John", email = "test@test.net", password = "189_23Ejq3oq2-<>!")
        val res =client.post("/auth/create", user)
        assertThat(res.code).withFailMessage { res.body!!.string() } .isEqualTo(200)
    }

    @Test
    fun `POST to create user with invalid email fails`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "John", email = "", password = "189_23Ejq3oq2-<>!")
        val res = client.post("/auth/create", user)
        assertThat(res.code).withFailMessage { res.body!!.string() }.isEqualTo(400)
    }

    @Test
    fun `POST to create user with unsafe password fails`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "John", email = "test@test.net", password = "1234")
        assertThat(client.post("/auth/create", user)).matches({ it.code == 400 }, "fails to create")
    }

    @Test
    fun `POST to create user with empty name fails`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "", email = "test@test.net", password = "189_23Ejq3oq2-<>!")
        assertThat(client.post("/auth/create", user)).matches({ it.code == 400 }, "fails to create")
    }

    @Test
    fun `GET to verify user succeeds`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "John", email = "test@test.net", password = "189_23Ejq3oq2-<>!")
        val create = client.post("/auth/create", user)
        assertThat(create.code).withFailMessage { create.body!!.string() }.isEqualTo(200)
        val mail = dumbster.receivedEmails.first().body
        val match = "https://${app.host}:${app.app.port()}/auth/verify/(\\S+)".toRegex().find(mail)
        assertThat(match).isNotNull
        val verify = client.get("/auth/verify/${match!!.groupValues[1]}")
        assertThat(verify.code).withFailMessage { verify.body!!.string() }.isEqualTo(200)
    }

    @Test
    fun `POST to login succeeds`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "John", email = "test@test.net", password = "189_23Ejq3oq2-<>!")
        val credentials = Login(email = user.email, password = user.password)
        val create = client.post("/auth/create", user)
        assertThat(create.code).withFailMessage { create.body!!.string() }.isEqualTo(200)
        val login = client.post("/auth/verify", credentials)
        assertThat(login.code).withFailMessage { login.body!!.string() }.isEqualTo(200)
    }

    @Test
    fun `POST to create unverified user succeeds`() = JavalinTest.test(app.app) { _, client ->
        val user = CreateUser(name = "John", email = "test@test.net", password = "189_23Ejq3oq2-<>!")
        val create = client.post("/auth/create", user)
        val create2 = client.post("/auth/create", user)
        assertThat(create.code).withFailMessage { create.body!!.string() }.isEqualTo(200)
        assertThat(create2.code).withFailMessage { create2.body!!.string() }.isEqualTo(200)
    }
}