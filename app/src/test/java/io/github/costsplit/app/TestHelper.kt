package io.github.costsplit.app

import com.dumbster.smtp.SimpleSmtpServer
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.costsplit.app.App.Companion.nextSalt
import io.github.costsplit.app.AppTest.AppService
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import kotlin.reflect.KProperty

private class ResetManager {
    private val resettables = mutableListOf<Resettable<Any>>()
    fun reset() {
        resettables.forEach { it.reset() }
    }
    fun <T : Any> manage(cleaner: (T) -> Unit = {}, getter: () -> T): Resettable<T> {
        val value = Resettable(getter, cleaner)
        resettables.add(value)
        return value
    }
}

private class Resettable<out T : Any>(private val getter: () -> T, private val clean: (T) -> Unit) {
    private var compute: T? = null
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

private val mngr = ResetManager()

private var dumbster: SimpleSmtpServer? = null
fun withMail() {
    dumbster = SimpleSmtpServer.start(SimpleSmtpServer.AUTO_SMTP_PORT)
}

val appService: AppService by mngr.manage { AppTest.retrofit() }

private val dataSource by mngr.manage(
    getter = {
        HikariDataSource(
            HikariConfig().apply {
                jdbcUrl = "jdbc:h2:mem:test"
                driverClassName = org.h2.Driver::class.qualifiedName
            }
        )
    },
    cleaner = {
        it.close()
    }
)
private val dbConnection by mngr.manage(
    getter = {
        Database.connect(datasource = dataSource)
    }, cleaner = {
        transaction(it) {
            close()
        }
    }
)

val app by mngr.manage(
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
    }, cleaner = {
        it.stop()
    })

fun reset() {
    mngr.reset()
    dumbster?.close()
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