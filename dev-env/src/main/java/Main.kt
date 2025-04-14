import com.dumbster.smtp.SimpleSmtpServer
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.cdimascio.dotenv.dotenv
import io.github.costsplit.api.DefaultApi
import io.github.costsplit.app.App
import io.github.costsplit.api.model.CreateUser
import io.github.costsplit.api.invoker.ApiClient
import org.jetbrains.exposed.sql.Database

fun main() {
    val dt = dotenv()

    val dataSource = HikariDataSource(
        HikariConfig().apply {
            jdbcUrl = dt["CS_DB_URL"]
            username = dt["CS_DB_USER"]
            password = dt["CS_DB_PASSWORD"]
            driverClassName = dt["CS_DB_DRIVER"]
        }
    )
    val dumbster = SimpleSmtpServer.start(dt["CS_SMTP_PORT"].toInt())

    val app = App(
        host = dt["CS_HOST"],
        port = dt["CS_PORT"].toInt(),
        smtpHost = dt["CS_SMTP_HOST"],
        smtpPort = dt["CS_SMTP_PORT"].toInt(),
        senderMail = dt["CS_SENDER_MAIL"],
        senderPassword = dt["CS_SENDER_PASSWORD"],
        secret = dt["CS_SECRET"],
        saltSecret = dt["CS_SALT_SECRET"].chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
        database = Database.connect(datasource = dataSource)
    )
    app.start()
    val api = DefaultApi(ApiClient().apply {
        setHost(dt["CS_HOST"])
        setPort(dt["CS_PORT"].toInt())
    })

    api.createUser(CreateUser().apply {
        name = "John"
        email = "john@test.net"
        password = "JohnPass@1"
    })
    val mail = dumbster.receivedEmails.first().body
    val tok = "https://.+/verify/(\\S+)".toRegex().find(mail)!!.groupValues[1]
    val verifiedTok = api.verifyUser(tok)

    val unverifiedTok = api.createUser(CreateUser().apply {
        name = "unverified"
        email = "unverified@test.net"
        password = "Unverified@1"
    })

    println(
        """
            Token for verified user: $verifiedTok
            Token for unverified user: $unverifiedTok
        """.trimIndent()
    )

    Runtime.getRuntime().addShutdownHook(Thread {
        app.close()
        dataSource.close()
        dumbster.close()
    })
}