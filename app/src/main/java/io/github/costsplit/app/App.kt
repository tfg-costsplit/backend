package io.github.costsplit.app

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.github.costsplit.api.Request
import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.http.*
import javalinjwt.JWTProvider
import org.apache.commons.mail.DefaultAuthenticator
import org.apache.commons.mail.EmailException
import org.apache.commons.mail.SimpleEmail
import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.exceptions.ExposedSQLException
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
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
    internal val idProvider: JWTProvider<User>
    internal val authProvider: JWTProvider<Int>

    init {
        val algorithm = Algorithm.HMAC256(secret)
        val verifier = JWT.require(algorithm).build()
        authProvider = JWTProvider(algorithm, { id, alg ->
            JWT.create()
                .withJWTId("auth")
                .withClaim("id", id)
                .withExpiresAt(Instant.now() + Duration.ofMinutes(30))
                .sign(alg)
        }, verifier)
        idProvider = JWTProvider(algorithm, { user, alg ->
            JWT.create()
                .withJWTId(user.emitter)
                .withClaim("id", user.id)
                .withClaim("verified", user.verified)
                .sign(alg)
        }, verifier)
        require(saltSecret.size == 16)
    }

    companion object {
        internal data class User(
            val id: Int,
            val verified: Boolean,
            val emitter: String,
        )

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
        transaction(database) {
            SchemaUtils.create(Credential)
        }
        app.start(host, port)
    }

    fun stop() {
        app.stop()
    }

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
                         try {
                            Credential.insertAndGetId {
                                it[email] = body.email
                                it[name] = body.name
                                it[Credential.salt] = salt
                                it[Credential.hash] = hash
                            }
                        } catch (e: ExposedSQLException) {
                            throw BadRequestResponse("Email already in use")
                        }
                    }

                    sendMail(
                        receiver = body.email, mailSubject = "COSTSPLIT: Account confirmation", body = """
                        Hello ${body.name}!
                        We are sending you this message so you can confirm the creation of your account.
                        In order to verify please follow this link:
                        https://$host:$port/verify/${authProvider.generateToken(id.value)}
                    """.trimIndent()
                    )
                    ctx.result(
                        idProvider.generateToken(
                            User(
                                id = id.value,
                                verified = false,
                                emitter = "create",
                            )
                        )
                    )
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
                            } catch (e: ExposedSQLException) {
                                throw UnauthorizedResponse("Invalid password or email")
                            }
                        val hash = hashPassword(body.password, user[Credential.salt])
                        if (!hash.contentEquals(user[Credential.hash])) {
                            throw UnauthorizedResponse("Invalid password or email")
                        }
                        ctx.result(
                            idProvider.generateToken(
                                User(
                                    id = user[Credential.id].value,
                                    emitter = "verify",
                                    verified = user[Credential.verified],
                                )
                            )
                        )
                    }
                    get("{token}") { ctx ->
                        val token = ctx.pathParam("token").let { authProvider.validateToken(it) }
                            .orElseThrow { ForbiddenResponse("Invalid token") }
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
}