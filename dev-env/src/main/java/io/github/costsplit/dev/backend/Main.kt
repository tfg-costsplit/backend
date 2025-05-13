package io.github.costsplit.dev.backend

import com.dumbster.smtp.SimpleSmtpServer
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.cdimascio.dotenv.dotenv
import io.github.costsplit.api.DefaultApi
import io.github.costsplit.api.invoker.ApiClient
import io.github.costsplit.api.model.CreateUser
import io.github.costsplit.api.model.Login
import io.github.costsplit.app.App
import org.jetbrains.exposed.sql.Database

fun main() {
    val dt = dotenv()

    val dataSource = HikariDataSource(
        HikariConfig().apply {
            jdbcUrl = dt["CS_DB_URL"]
            username = dt["CS_DB_USER"]
            password = dt["CS_DB_PASSWORD"]
            driverClassName = dt["CS_DB_DRIVER"]
        })
    val dumbster = SimpleSmtpServer.start(dt["CS_SMTP_PORT"].toInt())

    val app = App(
        host = dt["CS_HOST"],
        port = dt["CS_PORT"].toInt(),
        smtpHost = dt["CS_SMTP_HOST"],
        smtpPort = dumbster.port,
        senderMail = dt["CS_SENDER_MAIL"],
        senderPassword = dt["CS_SENDER_PASSWORD"],
        secret = dt["CS_SECRET"],
        saltSecret = dt["CS_SALT_SECRET"].chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
        database = Database.connect(datasource = dataSource)
    )
    app.start()

    Runtime.getRuntime().addShutdownHook(Thread {
        app.close()
        dataSource.close()
        dumbster.close()
    })

    val client = ApiClient().setHost(dt["CS_HOST"]).setPort(dt["CS_PORT"].toInt())
    val api = DefaultApi(client)

    val verifiedUser = CreateUser().apply {
        name = "John"
        email = "john@test.net"
        password = "JohnPass@1"
    }

    api.createUser(verifiedUser)
    val mail = dumbster.receivedEmails.first().body
    val tok = "https://.+/verify/(\\S+)".toRegex().find(mail)!!.groupValues[1]
    api.verifyUser(tok)
    val verifiedToken = api.loginUser(Login().apply {
        email = verifiedUser.email
        password = verifiedUser.password
    }).token

    dumbster.reset()

    val unverifiedUser = CreateUser().apply {
        name = "unverified"
        email = "unverified@test.net"
        password = "Unverified@1"
    }
    val unverifiedTok = api.createUser(unverifiedUser).token

    println(
        """
        Token for verified user: $verifiedToken
        Data of verified user:
        """.trimIndent()
    )
    println(verifiedUser)
    println(
        """
        Token for unverified user: $unverifiedTok
        Data of unverified user:
        """.trimIndent()
    )
    println(unverifiedUser)

    generateSequence(Unit) {
        dumbster.reset()
        Thread.sleep(1000)
    }.flatMap { dumbster.receivedEmails }.forEach {
        println(it)
    }
}