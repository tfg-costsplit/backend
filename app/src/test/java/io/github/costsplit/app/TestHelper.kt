package io.github.costsplit.app

import com.dumbster.smtp.SimpleSmtpServer
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.costsplit.app.App.Companion.nextSalt
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import kotlin.reflect.KProperty

private class Resettable<T : Any>(private val getter: () -> T, private val clean: (T) -> Unit) {
    constructor(value: () -> T) : this(value, {})

    var compute: T? = null
    operator fun getValue(thisRef: Any?, property: KProperty<*>): T {
        if (compute == null)
            compute = getter()
        return compute as T
    }

    fun reset() {
        compute?.let(clean)
        compute = null
    }
}

private var dumbster: SimpleSmtpServer? = null
fun withMail() {
    dumbster = SimpleSmtpServer.start(SimpleSmtpServer.AUTO_SMTP_PORT)
}

private val emptyAppService = Resettable {
    AppTest.retrofit()
}
val appService by emptyAppService

private val emptyDataSource = Resettable(
    getter = {
        HikariDataSource(
            HikariConfig().apply {
                jdbcUrl = "jdbc:h2:mem:test"
                driverClassName = org.h2.Driver::class.qualifiedName
                maximumPoolSize = 6
                isReadOnly = false
                transactionIsolation = "TRANSACTION_SERIALIZABLE"
            }
        )
    },
    clean = {
        it.close()
    }
)
val dataSource by emptyDataSource

private var emptyDbConnection = Resettable(
    getter = {
        val db = Database.connect(datasource = dataSource)
        transaction(db) {
            SchemaUtils.create(App.Companion.Credential)
        }
        db
    }, clean = {
        transaction(it) {
            close()
        }
    }
)
val dbConnection by emptyDbConnection

private var emptyApp = Resettable(
    getter = {
        val app = App(
            database = dbConnection,
            secret = "1234",
            senderMail = "sender@test.net",
            senderPassword = "1234",
            smtpHost = "localhost",
            smtpPort = dumbster?.port ?: 25,
            saltSecret = nextSalt(),
        )
        app.start()
        app
    }, clean = {
        it.stop()
    })
val app by emptyApp

fun reset() {
    emptyApp.reset()
    emptyDbConnection.reset()
    emptyDataSource.reset()
    emptyAppService.reset()
}

fun insertUser(userEmail: String, password: String): Int {
    val userSalt = nextSalt()
    val userHash = app.hashPassword(password, userSalt)
    return transaction(dbConnection) {
        with(App.Companion.Credential) {
            insert {
                it[name] = ""
                it[email] = userEmail
                it[salt] = userSalt
                it[hash] = userHash
            }[id].value
        }
    }
}