import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.cdimascio.dotenv.dotenv
import io.github.costsplit.app.App
import org.jetbrains.exposed.sql.Database

fun main() {
    val dt = dotenv()
    App(
        host = dt["CS_HOST"],
        port = dt["CS_PORT"].toInt(),
        smtpHost = dt["CS_SMTP_HOST"],
        smtpPort = dt["CS_SMTP_PORT"].toInt(),
        senderMail = dt["CS_SENDER_MAIL"],
        senderPassword = dt["CS_SENDER_PASSWORD"],
        secret = dt["CS_SECRET"],
        saltSecret = dt["CS_SALT_SECRET"].chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
        database = Database.connect(datasource = HikariDataSource(
            HikariConfig().apply {
                jdbcUrl = dt["CS_DB_URL"]
                username = dt["CS_DB_USER"]
                password = dt["CS_DB_PASSWORD"]
                driverClassName = dt["CS_DB_DRIVER"]
            }
        ))
    )
}