package io.github.costsplit.app

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import io.github.costsplit.api.Request
import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.http.*
import org.apache.commons.mail.DefaultAuthenticator
import org.apache.commons.mail.EmailException
import org.apache.commons.mail.SimpleEmail
import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.exceptions.ExposedSQLException
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.time.Duration.Companion.seconds

class App(
    val host: String = "localhost",
    val port: Int = 8080,
    secret: String,
    private val smtpHost: String = "smtp.gmail.com",
    private val smtpPort: Int = 25,
    private val senderMail: String,
    private val senderPassword: String,
    private val database: Database,
    private val saltSecret: ByteArray = nextSalt(),
) {
    private val algorithm: Algorithm = Algorithm.HMAC256(secret)
    private val verifier: JWTVerifier = JWT.require(algorithm).build()

    init {
        require(saltSecret.size == 16)
    }

    companion object {
        internal fun nextSalt(): ByteArray {
            val rnd = SecureRandom()
            val salt = ByteArray(16)
            rnd.nextBytes(salt)
            return salt
        }

        internal object Credential : IntIdTable("credential") {
            val email = varchar("email", 254).uniqueIndex()
            val name = varchar("name", 64)
            val salt = binary("salt", 32)
            val hash = binary("hash", 32)
            val verified = bool("verified").default(false)
        }
    }

    internal fun hashPassword(password: String, salt: ByteArray): ByteArray {
        val composite = salt + saltSecret
        val spec = PBEKeySpec(password.toCharArray(), composite, 65536, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val key = factory.generateSecret(spec).encoded
        return key
    }

    private fun sendMail(receiver: String, mailSubject: String, body: String) {
        val mail = SimpleEmail().apply {
            hostName = smtpHost
            setSmtpPort(this@App.smtpPort)
            authenticator = DefaultAuthenticator(senderMail, senderPassword)
            try {
                setFrom(senderMail)
            } catch (e: EmailException) {
                throw InternalServerErrorResponse("Something went wrong with out email service")
            }
            subject = mailSubject
            try {
                addTo(receiver)
            } catch (e: EmailException) {
                throw BadRequestResponse("Invalid email")
            }
            try {
                setMsg(body)
            } catch (e: EmailException) {
                throw InternalServerErrorResponse("Couldn't generate email message")
            }
        }
        try {
            mail.send()
        } catch (e: EmailException) {
            throw InternalServerErrorResponse("Couldn't send confirmation mail")
        }
    }

    fun start() {
        app.start(host, port)
    }

    fun stop() {
        app.stop()
    }

    internal fun genVerificationJwt(id: Int): String = JWT.create()
        .withClaim("id", id)
        .withJWTId("create")
        .withExpiresAt(Instant.now() + Duration.ofMinutes(30))
        .sign(algorithm)

    internal fun genUserJwt(id: Int, verified: Boolean = false): String = JWT.create()
        .withClaim("id", id)
        .withClaim("verified", verified)
        .withJWTId("verify")
        .sign(algorithm)

    private val app = Javalin.create { config ->
        config.jetty.modifyServer { server ->
            server.stopTimeout = 5.seconds.inWholeMilliseconds
        }
        config.router.apiBuilder {
            path("auth") {
                post("create") { ctx ->
                    val body = ctx.bodyAsClass<Request.CreateUser>()
                    val salt = nextSalt()
                    val hash = hashPassword(body.password, salt)
                    val id = transaction(database) {
                        val user = try {
                            Credential.insert {
                                it[email] = body.email
                                it[name] = body.name
                                it[Credential.salt] = salt
                                it[Credential.hash] = hash
                            }
                        } catch (e: ExposedSQLException) {
                            throw BadRequestResponse("Email already in use")
                        }
                        user[Credential.id]
                    }

                    sendMail(
                        receiver = body.email, mailSubject = "COSTSPLIT: Account confirmation", body = """
                        Hello ${body.name}!
                        We are sending you this message so you can confirm the creation of your account.
                        In order to verify please follow this link:
                        https://$host:$port/verify/${genVerificationJwt(id.value)}
                    """.trimIndent()
                    )
                    ctx.result(genUserJwt(id.value))
                }
                path("verify") {
                    post { ctx ->
                        val body = ctx.bodyAsClass<Request.Login>()
                        val user =
                            try {
                                transaction(database) {
                                    with(Credential) {
                                        select(id, salt, hash, verified).where { email eq body.email }.single()
                                    }
                                }
                            } catch (e: Exception) {
                                throw UnauthorizedResponse("Invalid password or email")
                            }
                        val hash = hashPassword(body.password, user[Credential.salt])
                        if (!hash.contentEquals(user[Credential.hash])) {
                            throw UnauthorizedResponse("Invalid password or email")
                        }
                        ctx.result(genUserJwt(user[Credential.id].value, user[Credential.verified]))
                    }
                    get("{token}") { ctx ->
                        val encodedToken = ctx.pathParam("token")
                        val token =
                            try {
                                verifier.verify(encodedToken)
                            } catch (e: JWTVerificationException) {
                                throw ForbiddenResponse("Invalid token")
                            }
                        transaction(database) {
                            Credential.update({ Credential.id eq token.getClaim("id").asInt() }) {
                                it[verified] = true
                            }
                        }
                    }
                }
            }
        }
    }
        .beforeMatched { ctx ->

        }
}