package io.github.costsplit.app

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.http.*
import io.javalin.openapi.*
import io.javalin.openapi.plugin.OpenApiPlugin
import io.javalin.openapi.plugin.swagger.SwaggerPlugin
import javalinjwt.JWTProvider
import javalinjwt.JavalinJWT
import org.apache.commons.mail.DefaultAuthenticator
import org.apache.commons.mail.EmailException
import org.apache.commons.mail.SimpleEmail
import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.jvm.optionals.getOrElse
import kotlin.jvm.optionals.getOrNull
import kotlin.time.Duration.Companion.seconds

internal data class AddPurchase(
    val groupId: Int,
    val description: String,
    val cost: ULong,
    val payments: Map<Int, Long>,
)

internal data class UserData(
    val id: Int,
    val name: String,
    val email: String,
    val token: String,
)

private data class UserToken(
    val id: Int,
    val verified: Boolean,
    val emitter: String,
)

private fun nextSalt(): ByteArray {
    val rnd = SecureRandom()
    val salt = ByteArray(16)
    rnd.nextBytes(salt)
    return salt
}

private object User : IntIdTable("user") {
    val email = varchar("email", 254).uniqueIndex()
    val name = varchar("name", 64)
    val salt = binary("salt", 32)
    val hash = binary("hash", 32)
    val verified = bool("verified").default(false)
}

private object Group : IntIdTable("group") {
    val name = varchar("name", 256)
}

private object GroupUser : Table("group-user") {
    val group = reference("group", Group.id)
    val user = reference("user", User.id)
    override val primaryKey = PrimaryKey(group, user)
}

private object Purchase : IntIdTable("purchase") {
    val group = reference("group", Group.id)
    val cost = ulong("cost")
    val description = varchar("description", 128)
}

private object Payment : IntIdTable("payment")

private data class JsonErrorResponse(
    val title: String,
    val status: Int,
    val type: String,
    val details: Map<String, String>,
)

internal data class CreateUser(
    val name: String,
    val email: String,
    val password: String,
)

internal data class Login(
    val email: String,
    val password: String,
)

private val DecodedJWT.verified: Boolean
    get() = this["verified"]

private inline operator fun <reified T> DecodedJWT.get(name: String): T {
    return getClaim(name).`as`(T::class.java)
}

private val emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\$".toRegex()
private fun String.isValidEmail(): Boolean = matches(emailRegex) && length <= 254
private fun String.validatePassword(): String? = when {
    length < 8 -> "Password must be at least 8 characters long"
    any { it.isWhitespace() } -> "Password mustn't contain whitespace"
    !any { it.isDigit() } -> "Password must contain at least one digit"
    !any { it.isUpperCase() } -> "Password must contain at least one uppercase character"
    !any { it.isLowerCase() } -> "Password must contain at least one lowercase character"
    all { it.isLetterOrDigit() } -> "Password must contain at least one special character, such as: _%-=+#@"
    else -> null
}

class App(
    internal val host: String = "localhost",
    private val port: Int = 8080,
    secret: String,
    private val smtpHost: String = "smtp.gmail.com",
    private val smtpPort: Int = 25,
    private val senderMail: String,
    private val senderPassword: String,
    private val database: Database,
    private val saltSecret: ByteArray = nextSalt(),
) : AutoCloseable {
    private val idProvider: JWTProvider<UserToken>
    private val authProvider: JWTProvider<Int>

    init {
        val algorithm = Algorithm.HMAC256(secret)
        val verifier = JWT.require(algorithm).build()
        authProvider = JWTProvider(algorithm, { id, alg ->
            JWT.create().withJWTId("auth").withClaim("id", id).withExpiresAt(Instant.now() + Duration.ofMinutes(30))
                .sign(alg)
        }, verifier)
        idProvider = JWTProvider(algorithm, { user, alg ->
            JWT.create().withJWTId(user.emitter).withClaim("id", user.id).withClaim("verified", user.verified)
                .withExpiresAt(Instant.now() + Duration.ofDays(14)).sign(alg)
        }, verifier)
        require(saltSecret.size == 16)
    }

    private fun hashPassword(password: String, salt: ByteArray): ByteArray {
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
        app.start()
    }

    @OpenApi(
        operationId = "createUser",
        path = "/auth/create",
        summary = "Create an user in the database with pending verification",
        description = """
            An unverified user can only store account details in the server.
            An unverified user may join a group trough an invite, but it won't be able to add purchases.
            An unverified user may have their account details, including the password, modified if another request for registering is done with the same email.
            Returns a JWT for future requests.
        """,
        methods = [HttpMethod.POST],
        requestBody = OpenApiRequestBody([OpenApiContent(CreateUser::class)]),
        responses = [
            OpenApiResponse("400", [OpenApiContent(JsonErrorResponse::class), OpenApiContent(String::class)]),
            OpenApiResponse(
                "200", [OpenApiContent(UserData::class)], "User data and JWT for authenticating in future requests"
            ),
        ],
    )
    private fun createUser(ctx: Context) {
        val body = ctx.bodyAsClass<CreateUser>()
        if (!body.email.isValidEmail()) throw BadRequestResponse("Invalid email")
        body.password.validatePassword()?.let { throw BadRequestResponse(it) }
        if (body.name.isEmpty()) throw BadRequestResponse("Empty username")
        if (body.name.length >= 64) throw BadRequestResponse("Name is too long")

        val id = transaction(database) {
            val usr = User.select(User.verified, User.id).where { User.email eq body.email }.firstOrNull()
            if (usr?.get(User.verified) == true) throw BadRequestResponse("Email already in use")
            val salt = nextSalt()
            val hash = hashPassword(body.password, salt)
            if (usr == null) {
                User.insertAndGetId {
                    it[email] = body.email
                    it[name] = body.name
                    it[User.salt] = salt
                    it[User.hash] = hash
                }
            } else {
                User.update({ User.id eq usr[User.id] }) {
                    it[name] = body.name
                    it[User.salt] = salt
                    it[User.hash] = hash
                }
                usr[User.id]
            }
        }

        sendMail(
            receiver = body.email, mailSubject = "COSTSPLIT: Account confirmation", body = """
                        Hello ${body.name}!
                        We are sending you this message so you can confirm the creation of your account.
                        In order to verify please follow this link:
                        https://$host:${app.port()}/auth/verify/${authProvider.generateToken(id.value)}
                    """.trimIndent().replace("\n", "\r\n")
        )
        ctx.json(
            UserData(
                id = id.value, name = body.name, email = body.email, token = idProvider.generateToken(
                    UserToken(
                        id = id.value,
                        verified = false,
                        emitter = "create",
                    )
                )
            )
        )
    }

    @OpenApi(
        operationId = "loginUser",
        path = "/auth/verify",
        summary = "Log a user in",
        description = """
            Log a user into the server trough authentication credentials and return a JWT for future requests.
        """,
        methods = [HttpMethod.POST],
        requestBody = OpenApiRequestBody([OpenApiContent(Login::class)]),
        responses = [
            OpenApiResponse("401", [OpenApiContent(JsonErrorResponse::class), OpenApiContent(String::class)]),
            OpenApiResponse(
                "200", [OpenApiContent(UserData::class)], "User data and JWT for authenticating in future requests"
            ),
        ],
    )
    private fun login(ctx: Context) {
        val body = ctx.bodyAsClass<Login>()
        val user = transaction(database) {
            with(User) {
                select(id, name, salt, hash, verified).where { email eq body.email }.singleOrNull()
            }
        } ?: throw UnauthorizedResponse("Invalid password or email")
        val hash = hashPassword(body.password, user[User.salt])
        if (!hash.contentEquals(user[User.hash])) throw UnauthorizedResponse("Invalid password or email")
        ctx.json(
            UserData(
                id = user[User.id].value, name = user[User.name], email = body.email, token = idProvider.generateToken(
                    UserToken(
                        id = user[User.id].value,
                        emitter = "verify",
                        verified = user[User.verified],
                    )
                )
            )
        )
    }

    private fun Context.getToken(): DecodedJWT? =
        JavalinJWT.getTokenFromHeader(this).flatMap(idProvider::validateToken).getOrNull()

    @OpenApi(
        operationId = "verifyUser",
        path = "/auth/verify/{token}",
        summary = "Confirm the email of an account",
        description = """
            Confirm the email of an account.
        """,
        methods = [HttpMethod.GET],
        pathParams = [OpenApiParam("token", String::class, "Auth JWT")],
        responses = [
            OpenApiResponse(
                "403",
                [OpenApiContent(JsonErrorResponse::class), OpenApiContent(String::class), OpenApiContent(mimeType = "text/html")]
            ),
            OpenApiResponse("200", [OpenApiContent(mimeType = "text/html")], "Account confirmation response"),
        ],
    )
    private fun verify(ctx: Context) {
        val supportsHtml = ctx.header("Accept")?.contains("text/html") ?: false
        val jwt = ctx.pathParam("token").let(authProvider::validateToken).getOrElse {
            if (supportsHtml) ctx.html("<h1>Couldn't confirm account</h1>")
            throw BadRequestResponse("Invalid/Missing token")
        }
        transaction(database) {
            User.update({ User.id eq jwt.get<Int>("id") }) {
                it[verified] = true
            }
        }
        if (supportsHtml) ctx.html("<h1>Account confirmed</h1>")
    }

    @OpenApi(
        operationId = "createGroup",
        path = "/group/{name}",
        summary = "Create a new group",
        description = """
            Create an empty group for the user and return the group id
        """,
        methods = [HttpMethod.POST],
        pathParams = [OpenApiParam("name", String::class, "Name of the group")],
        security = [OpenApiSecurity("Bearer")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(Int::class, "Group id")])]
    )
    private fun createGroup(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        if (!jwt.verified) throw UnauthorizedResponse("User must be verified")
        val groupName = ctx.pathParam("name")
        if (groupName.length > 256) throw BadRequestResponse("Group name is too long, limit is 256 bytes")
        val id = transaction(database) {
            val groupId = Group.insertAndGetId {
                it[name] = groupName
            }
            GroupUser.insert {
                it[group] = groupId
                it[user] = jwt.get<Int>("id")
            }
            groupId
        }
        ctx.json(id.value)
    }

    @OpenApi(
        operationId = "createPurchase",
        path = "/purchase",
        summary = "Create a purchase",
        description = """
            Store a purchase and how it's supposed to be paid.
            The user must be a member of the provided group.
        """,
        methods = [HttpMethod.POST],
        requestBody = OpenApiRequestBody([OpenApiContent(AddPurchase::class)]),
        security = [OpenApiSecurity("Bearer")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(Int::class, "Purchase id")])]
    )
    private fun createPurchase(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        if (!jwt.verified) throw UnauthorizedResponse("User must be verified")
        val body: AddPurchase = ctx.bodyAsClass()
        val id = transaction(database) {
            val exists = !GroupUser.selectAll()
                .where { (GroupUser.group eq body.groupId) and (GroupUser.user eq jwt.get<Int>("id")) }.empty()
            if (!exists) throw NotFoundResponse("Group not found")
            Purchase.insertAndGetId {
                it[group] = body.groupId
                it[cost] = body.cost
                it[description] = body.description
            }
        }
        ctx.json(id.value)
    }

    internal val app = Javalin.create { config ->
        config.jetty.defaultPort = port
        config.events.serverStarting {
            transaction(database) {
                SchemaUtils.create(User, Group, Purchase, GroupUser)
            }
        }
        config.jetty.modifyServer { server ->
            server.stopTimeout = 5.seconds.inWholeMilliseconds
        }
        config.registerPlugin(OpenApiPlugin { openApiConfig ->
            openApiConfig.withDefinitionConfiguration { _, definition ->
                definition.withInfo { info ->
                    info.title = "COSTSPLIT API"
                }
                definition.withSecurity {
                    it.withBearerAuth("Bearer") { BearerAuth() }
                }
            }
            openApiConfig.withDocumentationPath("/openapi.json")
        })
        config.registerPlugin(SwaggerPlugin { swaggerConfig ->
            swaggerConfig.title = "OpenApi documentation"
            swaggerConfig.uiPath = "/api"
            swaggerConfig.documentationPath = "/openapi.json"
        })
        config.router.apiBuilder {
            path("auth") {
                post("create", ::createUser)
                path("verify") {
                    post(::login)
                    get("{token}", ::verify)
                }
            }
            path("group") {
                post("{name}", ::createGroup)
            }
            path("purchase") {
                post(::createPurchase)
            }
        }
    }

    override fun close() {
        app.stop()
    }
}
