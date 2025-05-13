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
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
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
    val payments: Map<Int, PayEntry>,
)

internal data class UpdatePurchase(
    val description: String? = null,
    val cost: ULong? = null,
    val payments: Map<Int, PayEntry>? = null,
    val payer: Int? = null,
)

internal data class UserData(
    val id: Int,
    val name: String,
    val email: String,
    val token: String,
    val groups: List<Int>,
)

internal data class GroupData(
    val id: Int,
    val name: String,
    val purchases: List<Int>,
)

internal data class AllGroupData(
    val id: Int,
    val name: String,
    val purchases: List<PurchaseData>,
)

internal data class PayEntry(val paid: ULong, val shouldPay: ULong)

internal data class PurchaseData(
    val id: Int,
    val cost: ULong,
    val payer: Int,
    val description: String,
    val payments: Map<Int, PayEntry>,
)

private data class UserToken(
    val id: Int,
    val verified: Boolean,
    val emitter: String,
)

private data class Invite(
    val groupId: Int,
    val emitter: Int,
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
    val user = reference("user", User.id)
    val name = varchar("name", 256)
}

private object GroupUser : Table("group-user") {
    val groupId = reference("group", Group.id)
    val user = reference("user", User.id)
    override val primaryKey = PrimaryKey(groupId, user)
}

private object Purchase : IntIdTable("purchase") {
    val group = reference("group", Group.id)
    val payer = reference("payer", User.id)
    val cost = ulong("cost")
    val description = varchar("description", 128)
}

private object Payment : IntIdTable("payment") {
    val user = reference("user", User.id)
    val purchase = reference("purchase", Purchase.id)
    val paid = ulong("paid")
    val shouldPay = ulong("should_pay")
}

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
    private val inviteProvider: JWTProvider<Invite>

    init {
        require(saltSecret.size == 16)
        val algorithm = Algorithm.HMAC256(secret)
        val verifier = JWT.require(algorithm).build()
        authProvider = JWTProvider(algorithm, { id, alg ->
            JWT.create().withJWTId("auth").withClaim("id", id).withExpiresAt(Instant.now() + Duration.ofMinutes(30))
                .sign(alg)
        }, verifier)
        idProvider = JWTProvider(algorithm, { user, alg ->
            JWT.create().withJWTId("id").withClaim("id", user.id).withClaim("verified", user.verified)
                .withExpiresAt(Instant.now() + Duration.ofDays(14)).sign(alg)
        }, verifier)
        inviteProvider = JWTProvider(algorithm, { invite, alg ->
            JWT.create().withJWTId("invite").withClaim("group", invite.groupId).withClaim("emitter", invite.emitter)
                .withExpiresAt(Instant.now() + Duration.ofDays(7)).sign(alg)
        }, verifier)
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
                    """.trimIndent()
        )
        ctx.json(
            UserData(
                id = id.value,
                name = body.name,
                email = body.email,
                groups = emptyList(),
                token = idProvider.generateToken(
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
        val (user, groups) = transaction(database) {
            val user =
                User.select(User.id, User.name, User.salt, User.hash, User.verified).where { User.email eq body.email }
                    .singleOrNull() ?: throw UnauthorizedResponse("Invalid password or email")
            val hash = hashPassword(body.password, user[User.salt])
            if (!hash.contentEquals(user[User.hash])) throw UnauthorizedResponse("Invalid password or email")
            val groups = GroupUser.select(GroupUser.groupId).where { GroupUser.user eq user[User.id] }
                .map { it[GroupUser.groupId].value }.toList()
            user to groups
        }
        ctx.json(
            UserData(
                id = user[User.id].value,
                name = user[User.name],
                email = body.email,
                groups = groups,
                token = idProvider.generateToken(
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
        JavalinJWT.getTokenFromHeader(this).flatMap(idProvider::validateToken).filter { it.id == "id" }.getOrNull()

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
                "400", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
            ),
            OpenApiResponse("200", [OpenApiContent(mimeType = "text/html")], "Account confirmation response"),
        ],
    )
    private fun verify(ctx: Context) {
        val supportsHtml = ctx.header("Accept")?.contains("text/html") ?: false
        val jwt = ctx.pathParam("token").let(authProvider::validateToken).filter { it.id == "auth" }.getOrElse {
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
        path = "/group",
        summary = "Create a new group",
        description = """
            Create an empty group for the user and return the group id
        """,
        methods = [HttpMethod.POST],
        requestBody = OpenApiRequestBody([OpenApiContent(String::class)], description = "Group name"),
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "400", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(Int::class)], "Group id")]
    )
    private fun createGroup(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        if (!jwt.verified) throw UnauthorizedResponse("User must be verified")
        val groupName = ctx.body()
        if (groupName.length > 256) throw BadRequestResponse("Group name is too long, limit is 256 bytes")
        val userId: Int = jwt["id"]
        val id = transaction(database) {
            val id = Group.insertAndGetId {
                it[name] = groupName
                it[user] = userId
            }.value
            GroupUser.insert {
                it[groupId] = id
                it[user] = userId
            }
            id
        }
        ctx.json(id)
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
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "404", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(Int::class)], "Purchase id")]
    )
    private fun createPurchase(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        if (!jwt.verified) throw UnauthorizedResponse("User must be verified")
        val body: AddPurchase = ctx.bodyAsClass()
        val userId: Int = jwt["id"]
        val id = transaction(database) {
            val exists =
                !GroupUser.selectAll().where { (GroupUser.groupId eq body.groupId) and (GroupUser.user eq userId) }
                    .empty()
            if (!exists) throw NotFoundResponse("Group not found")
            val purchaseId = Purchase.insertAndGetId {
                it[group] = body.groupId
                it[payer] = userId
                it[cost] = body.cost
                it[description] = body.description
            }
            Payment.batchInsert(body.payments.entries) { (user, entry) ->
                this[Payment.user] = user
                this[Payment.paid] = entry.paid
                this[Payment.purchase] = purchaseId
                this[Payment.shouldPay] = entry.shouldPay
            }
            purchaseId
        }
        ctx.json(id.value)
    }

    @OpenApi(
        operationId = "updatePurchase",
        path = "/purchase/{id}",
        summary = "Update a purchase",
        description = """
            Update a purchase and how it's supposed to be paid.
            The user must be a member of the provided group.
        """,
        pathParams = [OpenApiParam("id", Int::class, "Id of the purchase")],
        methods = [HttpMethod.POST],
        requestBody = OpenApiRequestBody([OpenApiContent(UpdatePurchase::class)]),
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "404", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200")],
    )
    private fun updatePurchase(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        if (!jwt.verified) throw UnauthorizedResponse("User must be verified")
        val body: UpdatePurchase = ctx.bodyAsClass()
        val id = ctx.pathParamAsClass<Int>("id").getOrThrow { BadRequestResponse("Invalid/Missing purchase id") }
        val userId: Int = jwt["id"]
        transaction(database) {
            val notExists = GroupUser.selectAll().where {
                (GroupUser.user eq userId) and exists(
                    Purchase.selectAll().where { Purchase.group eq GroupUser.groupId })
            }.empty()
            if (notExists) throw NotFoundResponse("Purchase not found")
            Purchase.update({ Purchase.id eq id }) { row ->
                body.payer?.let { row[payer] = it }
                body.cost?.let { row[cost] = it }
                body.description?.let { row[description] = it }
            }
            body.payments?.let {
                Payment.deleteWhere { Payment.id eq id }
                Payment.batchInsert(it.entries) { (user, entry) ->
                    this[Payment.user] = user
                    this[Payment.paid] = entry.paid
                    this[Payment.purchase] = id
                    this[Payment.shouldPay] = entry.shouldPay
                }
            }
        }
    }

    @OpenApi(
        operationId = "getPurchaseData",
        path = "/purchase/{id}",
        summary = "Get information about a purchase",
        description = """
            Get all the information related to a purchase
        """,
        pathParams = [OpenApiParam("id", Int::class, "Id of the purchase")],
        methods = [HttpMethod.GET],
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "404", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(PurchaseData::class)])],
    )
    private fun getPurchaseData(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        val id = ctx.pathParamAsClass<Int>("id").getOrThrow { BadRequestResponse("Invalid/Missing purchase id") }
        val userId: Int = jwt["id"]
        val (purchase, payments) = transaction(database) {
            val purchase = Purchase.select(Purchase.cost, Purchase.description, Purchase.payer).where {
                exists(
                    GroupUser.selectAll()
                        .where { (GroupUser.groupId eq Purchase.group) and (GroupUser.user eq userId) })
            }.singleOrNull() ?: throw NotFoundResponse("Purchase not found")
            val payments =
                Payment.select(Payment.user, Payment.paid, Payment.shouldPay).where { Payment.purchase eq id }
                    .associate { it[Payment.user].value to PayEntry(it[Payment.paid], it[Payment.shouldPay]) }
            purchase to payments
        }
        ctx.json(
            PurchaseData(
                id = id,
                cost = purchase[Purchase.cost],
                description = purchase[Purchase.description],
                payer = purchase[Purchase.payer].value,
                payments = payments,
            )
        )
    }

    @OpenApi(
        operationId = "getGroupData",
        path = "/group/{id}",
        summary = "Get the data of a group",
        pathParams = [OpenApiParam("id", Int::class, "Group id")],
        description = """
            Retrieve id, name, and payment ids of a group
        """,
        methods = [HttpMethod.GET],
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "400", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "404", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(GroupData::class)], "Group data")]
    )
    private fun getGroupData(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        val groupId = ctx.pathParamAsClass<Int>("id").getOrThrow { BadRequestResponse("Invalid group id") }
        val userId: Int = jwt["id"]
        val (name, purchases) = transaction(database) {
            val group = GroupUser.select(GroupUser.groupId, GroupUser.user)
                .where { (GroupUser.groupId eq groupId) and (GroupUser.user eq userId) }.firstOrNull()
                ?: throw NotFoundResponse("Group not found")
            val name = Group.select(Group.name).where { Group.id eq group[GroupUser.groupId] }.single()[Group.name]
            val purchases =
                Purchase.select(Purchase.id).where { Purchase.group eq groupId }.map { it[Purchase.id].value }
            name to purchases
        }
        ctx.json(
            GroupData(
                id = groupId,
                name = name,
                purchases = purchases,
            )
        )
    }

    @OpenApi(
        operationId = "getAllGroupData",
        path = "/group-data/{id}",
        summary = "Get all the data of a group",
        pathParams = [OpenApiParam("id", Int::class, "Group id")],
        description = """
            Retrieve id, name, payments, and the respective purchases of a group
        """,
        methods = [HttpMethod.GET],
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "400", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "404", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(AllGroupData::class)], "Group data")]
    )
    private fun getAllGroupData(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/Missing token")
        val groupId = ctx.pathParamAsClass<Int>("id").getOrThrow { BadRequestResponse("Invalid group id") }
        val userId: Int = jwt["id"]
        val (name, purchases) = transaction(database) {
            val group = GroupUser.select(GroupUser.groupId, GroupUser.user)
                .where { (GroupUser.groupId eq groupId) and (GroupUser.user eq userId) }.firstOrNull()
                ?: throw NotFoundResponse("Group not found")
            val name = Group.select(Group.name).where { Group.id eq group[GroupUser.groupId] }.single()[Group.name]
            val payments = Payment.select(Payment.user, Payment.paid, Payment.shouldPay, Payment.purchase).where {
                exists(
                    Purchase.selectAll().where { (Purchase.group eq groupId) and (Purchase.id eq Payment.purchase) })
            }.map {
                it[Payment.purchase].value to (it[Payment.user].value to PayEntry(
                    it[Payment.paid], it[Payment.shouldPay]
                ))
            }.groupBy({ it.first }, { it.second }).mapValues { it.value.toMap() }
            val purchases = Purchase.select(Purchase.id, Purchase.description, Purchase.cost, Purchase.payer)
                .where { Purchase.group eq groupId }.map {
                    PurchaseData(
                        id = it[Purchase.id].value,
                        description = it[Purchase.description],
                        cost = it[Purchase.cost],
                        payer = it[Purchase.payer].value,
                        payments = payments[it[Purchase.id].value] ?: emptyMap()
                    )
                }
            name to purchases
        }

        ctx.json(
            AllGroupData(
                id = groupId,
                name = name,
                purchases = purchases,
            )
        )
    }

    @OpenApi(
        operationId = "joinGroup",
        path = "/group-join/{token}",
        summary = "Join a group",
        pathParams = [OpenApiParam("token", String::class, "Invite token")],
        description = """
            Makes an user join a group.
        """,
        methods = [HttpMethod.POST],
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "400", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200")]
    )
    private fun joinGroup(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/missing token")
        if (!jwt.verified) throw UnauthorizedResponse("User must be verified to join group")
        val token = ctx.pathParam("token")
        val invite = inviteProvider.validateToken(token).filter { it.id == "invite" }.getOrNull()
            ?: throw BadRequestResponse("Expired/Invalid invite")
        val group: Int = invite["group"]
        val uid: Int = jwt["id"]
        transaction(database) {
            GroupUser.insertIgnore {
                it[groupId] = group
                it[user] = uid
            }
        }
    }


    @OpenApi(
        operationId = "getGroupInvite",
        path = "/group-invite/{id}",
        summary = "Generate an invite for a group",
        pathParams = [OpenApiParam("id", Int::class, "Group id")],
        description = """
            Generate an invite token for a group.
            The endpoint for accepting the invite is "/group-join/{token}".
            The token expires after one week.
        """,
        methods = [HttpMethod.GET],
        security = [OpenApiSecurity("BearerAuth")],
        responses = [OpenApiResponse(
            "401", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse(
            "400", [OpenApiContent(String::class), OpenApiContent(JsonErrorResponse::class)]
        ), OpenApiResponse("200", [OpenApiContent(String::class)], "Invite token")]
    )
    private fun getGroupInvite(ctx: Context) {
        val jwt = ctx.getToken() ?: throw UnauthorizedResponse("Invalid/missing token")
        val uid: Int = jwt["id"]
        val gid = ctx.pathParamAsClass<Int>("id").getOrThrow { BadRequestResponse("Invalid group id") }
        val isMember = transaction(database) {
            !GroupUser.selectAll().where { (GroupUser.user eq uid) and (GroupUser.groupId eq gid) }.empty()
        }
        if (!isMember) throw NotFoundResponse("Group not found")
        val token = inviteProvider.generateToken(Invite(gid, uid))
        ctx.result(token)
    }

    internal val app = Javalin.create { config ->
        config.jetty.defaultPort = port
        config.events.serverStarting {
            transaction(database) {
                SchemaUtils.create(User, Group, GroupUser, Purchase, Payment)
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
                    it.withBearerAuth()
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
                post(::createGroup)
                get("{id}", ::getGroupData)
            }
            get("group-invite/{id}", ::getGroupInvite)
            post("group-join/{token}", ::joinGroup)
            get("group-data/{id}", ::getAllGroupData)
            path("purchase") {
                post(::createPurchase)
                post("{id}", ::updatePurchase)
                get("{id}", ::getPurchaseData)
            }
        }
    }

    override fun close() {
        app.stop()
    }
}
