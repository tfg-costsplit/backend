import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.costsplit.app.App
import org.jetbrains.exposed.sql.Database
import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient
import com.google.cloud.secretmanager.v1.SecretVersionName

fun accessSecret(projectId: String, secretId: String, versionId: String = "latest"): String {
    SecretManagerServiceClient.create().use { client ->
        val secretVersionName = SecretVersionName.of(projectId, secretId, versionId)
        val request = AccessSecretVersionRequest.newBuilder()
            .setName(secretVersionName.toString())
            .build()

        val response = client.accessSecretVersion(request)
        val payload = response.payload.data.toStringUtf8()
        return payload
    }
}

fun main() {
    val projectId = System.getenv("GOOGLE_CLOUD_PROJECT")
    val dataSource = HikariDataSource(
        HikariConfig().apply {
            jdbcUrl = accessSecret(projectId, "supabase-url")
            username = "postgres"
            password = accessSecret(projectId, "supabase-key")
            driverClassName = org.postgresql.Driver::class.qualifiedName
        })

    val app = App(
        smtpPort = 465,
        smtpHost = "smtp.gmail.com",
        port = System.getenv("PORT")?.toInt() ?: 8080,
        host = "costsplit-456211.oa.r.appspot.com",
        senderMail = System.getenv("CS_SENDER_MAIL"),
        senderPassword = accessSecret(projectId, "smtp-pass"),
        secret = accessSecret(projectId, "main-secret"),
        saltSecret = accessSecret(projectId, "salt").chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
        database = Database.connect(datasource = dataSource)
    )
    app.start()
    Runtime.getRuntime().addShutdownHook(Thread {
        app.close()
        dataSource.close()
    })
}
