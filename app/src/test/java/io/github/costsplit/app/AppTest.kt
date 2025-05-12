package io.github.costsplit.app

import com.dumbster.smtp.SimpleSmtpServer
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.javalin.Javalin
import io.javalin.json.JavalinJackson
import io.javalin.json.fromJsonString
import io.javalin.testtools.HttpClient
import io.javalin.testtools.JavalinTest
import okhttp3.Request
import okhttp3.Response
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.h2.Driver
import org.jetbrains.exposed.sql.Database
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AppTest {
    private lateinit var dumbster: SimpleSmtpServer
    private lateinit var dataSource: HikariDataSource
    private lateinit var app: App
    private val testUser = CreateUser(
        email = "test@test.net",
        name = "John",
        password = "q3oA2-<189_23Ej>!",
    )

    @BeforeEach
    fun setUp() {
        dumbster = SimpleSmtpServer.start(SimpleSmtpServer.AUTO_SMTP_PORT)
        dataSource = HikariDataSource(
            HikariConfig().apply {
                jdbcUrl = "jdbc:h2:mem:test;MODE=PostgreSQL"
                driverClassName = Driver::class.qualifiedName
            })
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

    private fun Request.Builder.jwt(token: String): Request.Builder {
        header("Authorization", "Bearer $token")
        return this
    }

    private fun Response.assertCode(expected: Int): Response {
        assertThat(code).withFailMessage { body?.string() ?: "Response body is null" }.isEqualTo(expected)
        return this
    }

    private fun CreateUser.create(client: HttpClient): Response = client.post("/auth/create", this)

    private fun CreateUser.verify(port: Int, client: HttpClient, builder: (Request.Builder) -> Unit = {}): Response {
        create(client).assertCode(200)
        val mail = dumbster.receivedEmails.last().body
        val match = "https://localhost:$port/auth/verify/(\\S+)".toRegex().find(mail)
        assertThat(match).isNotNull
        return client.get("/auth/verify/${match!!.groupValues[1]}", builder)
    }

    private val jackson = ObjectMapper().apply {
        registerModule(KotlinModule.Builder().build())
    }.let(::JavalinJackson)

    private inline fun <reified T> Response.parse(): T = jackson.fromJsonString(body!!.string())

    private fun CreateUser.login(port: Int, client: HttpClient): Response {
        verify(port, client).assertCode(200)
        return client.post("/auth/verify", toLogin())
    }

    private fun CreateUser.toLogin(): Login = Login(email = email, password = password)

    @AfterEach
    fun tearDown() {
        app.close()
        dataSource.close()
        dumbster.close()
    }


    private fun test(action: (Javalin, HttpClient) -> Unit) = JavalinTest.test(app.app, testCase = action)
    private fun test(action: (HttpClient) -> Unit) = test { _, client -> action(client) }

    @Test
    fun `POST to create user succeeds`() = test { client ->
        testUser.create(client).assertCode(200)
    }

    @Test
    fun `POST to create user with invalid email fails`() = test { client ->
        testUser.copy(email = "").create(client).assertCode(400)
        testUser.copy(email = "${"a".repeat(125)}@${"b".repeat(125)}.com").create(client).assertCode(400)
    }

    @Test
    fun `POST to create use with invalid name fails`() = test { client ->
        testUser.copy(name = "a".repeat(65)).create(client).assertCode(400)
        testUser.copy(name = "").create(client).assertCode(400)
    }

    @Test
    fun `App requires a salt of 16`() {
        assertThatThrownBy {
            App(
                database = Database.connect(datasource = dataSource),
                secret = "1234",
                senderMail = "sender@test.net",
                senderPassword = "1234",
                smtpHost = "localhost",
                smtpPort = dumbster.port,
                saltSecret = "x".repeat(15).toByteArray(),
            )
        }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `POST to create user with unsafe password fails`() = test { client ->
        testUser.copy(password = testUser.password.take(7)).create(client).assertCode(400)
        testUser.copy(password = "${testUser.password} ").create(client).assertCode(400)
        testUser.copy(password = testUser.password.lowercase()).create(client).assertCode(400)
        testUser.copy(password = testUser.password.uppercase()).create(client).assertCode(400)
        testUser.copy(password = testUser.password.map { if (it.isLetterOrDigit()) it else '0' }.joinToString(""))
            .create(client).assertCode(400)
        testUser.copy(password = testUser.password.map { if (it.isDigit()) 'a' else it }.joinToString(""))
            .create(client).assertCode(400)
    }

    @Test
    fun `GET to verify user succeeds`() = test { server, client ->
        testUser.verify(server.port(), client).assertCode(200)
        testUser.copy(email = "test2@test.net").verify(server.port(), client) {
            it.header("Accept", "text/html")
        }
    }

    @Test
    fun `GET to verify use with wrong token fails`() = test { client ->
        testUser.create(client).assertCode(200)
        client.get("/auth/verify/wrong").assertCode(400)
        client.get("/auth/verify/wrong") {
            it.header("Accept", "text/html")
        }.assertCode(400)
    }

    @Test
    fun `POST to login succeeds`() = test { server, client ->
        testUser.login(server.port(), client).assertCode(200).parse<UserData>()
    }

    @Test
    fun `POST to create unverified to change data succeeds`() = test { client ->
        testUser.create(client).assertCode(200)
        testUser.create(client).assertCode(200)
    }

    @Test
    fun `POST to create group succeeds`() = test { server, client ->
        val token: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        val response = client.post("/group/testGroup") {
            it.jwt(token.token)
        }
        response.assertCode(200).parse<Int>()
    }

    @Test
    fun `POST to create group without auth fails`() = test { client ->
        val user: UserData = testUser.create(client).assertCode(200).parse()
        client.post("/group/testName") { it.jwt(user.token) }.assertCode(401)
        client.post("/group/testName").assertCode(401)
    }

    @Test
    fun `POST to create purchase succeeds`() = test { server, client ->
        val userData: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        val groupId: Int = client.post("/group/testGroup") {
            it.jwt(userData.token)
        }.assertCode(200).parse()

        client.post(
            "/purchase", AddPurchase(
                groupId = groupId, cost = 100UL, description = "empty", payments = mapOf(
                    userData.id to 100UL
                )
            )
        ) {
            it.jwt(userData.token)
        }.assertCode(200).parse<Int>()
    }

    @Test
    fun `POST to create purchase in group that doesn't exist fails`() = test { server, client ->
        val userData: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        client.post(
            "/purchase", AddPurchase(
                groupId = 0, cost = 0UL, description = "", payments = mapOf()
            )
        ) {
            it.jwt(userData.token)
        }.assertCode(404)
    }

    @Test
    fun `POST to create purchase without auth fails`() = test { server, client ->
        val data: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        val groupId: Int = client.post("/group/testName") { it.jwt(data.token) }.assertCode(200).parse()
        client.post(
            "/purchase", AddPurchase(
                groupId = groupId,
                cost = 0UL,
                description = "",
                payments = mapOf(),
            )
        ).assertCode(401)

        val data2: UserData = testUser.copy(email = "test2@test.net").create(client).assertCode(200).parse()
        client.post(
            "/purchase", AddPurchase(
                groupId = groupId,
                cost = 0UL,
                description = "",
                payments = mapOf(),
            )
        ) {
            it.jwt(data2.token)
        }.assertCode(401)
    }

    @Test
    fun `POST to create user with already used email fails`() = test { server, client ->
        testUser.verify(server.port(), client).assertCode(200)
        testUser.create(client).assertCode(400)
    }

    @Test
    fun `POST to login with invalid credentials fails`() = test { client ->
        testUser.create(client).assertCode(200)
        client.post("/auth/verify", testUser.copy(email = "A").toLogin()).assertCode(401)
        client.post("/auth/verify", testUser.copy(password = "A").toLogin()).assertCode(401)
    }

    @Test
    fun `POST to create group with long name fails`() = test { server, client ->
        val data: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        client.post("/group/${"a".repeat(257)}") { it.jwt(data.token) }.assertCode(400)
    }

    @Test
    fun `POST to create purchase in non-owned group fails`() = test { server, client ->
        val data: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        val data2: UserData =
            testUser.copy(email = "test2@test.net").login(server.port(), client).assertCode(200).parse()
        val groupId: Int = client.post("/group/testName") { it.jwt(data.token) }.assertCode(200).parse()
        client.post(
            "/purchase", AddPurchase(
                groupId = groupId, cost = 0UL, description = "", payments = mapOf()
            )
        ) { it.jwt(data2.token) }.assertCode(404)
        client.post(
            "/purchase", AddPurchase(
                groupId = groupId, cost = 0UL, description = "", payments = mapOf()
            )
        ) { it.jwt(data.token) }.assertCode(200)
    }

    @Test
    fun `GET to request group data contains purchases`() = test { server, client ->
        val data: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        val gid: Int = client.post("/group/testGroup") { it.jwt(data.token) }.assertCode(200).parse()
        val pid: Int = client.post(
            "/purchase", AddPurchase(
                groupId = gid, cost = 0UL, description = "", payments = mapOf()
            )
        ) { it.jwt(data.token) }.assertCode(200).parse()
        val gdata: GroupData = client.get("/group/$gid") { it.jwt(data.token) }.assertCode(200).parse()
        assertThat(gdata.purchases).contains(pid)
        val allData: AllGroupData = client.get("/group-data/$gid") {
            it.jwt(data.token)
        }.assertCode(200).parse()
        assertThat(allData.purchases).contains(
            PurchaseData(
                id = pid,
                payer = data.id,
                cost = 0UL,
                description = "",
                payments = mapOf(),
            )
        )
    }

    @Test
    fun `GET to acquire group invite url works`() = test { server, client ->
        val data: UserData = testUser.login(server.port(), client).assertCode(200).parse()
        val data2: UserData = testUser.copy(email = "testuser2@mail.com").login(server.port(), client).assertCode(200).parse()
        val gid: Int = client.post("/group/testGroup") { it.jwt(data.token) }.assertCode(200).parse()
        val token: String = client.get("/group-invite/$gid") { it.jwt(data.token) }.assertCode(200).body!!.string()
        client.post("/group-join/$token") { it.jwt(data2.token) }.assertCode(200)
    }
}