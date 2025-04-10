package io.github.costsplit.app;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.github.costsplit.api.Request;
import io.github.costsplit.api.Response;
import io.github.costsplit.app.orm.Credential;
import io.javalin.Javalin;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.ForbiddenResponse;
import io.javalin.http.InternalServerErrorResponse;
import io.javalin.http.UnauthorizedResponse;
import lombok.Builder;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.apache.commons.mail.DefaultAuthenticator;
import org.apache.commons.mail.EmailException;
import org.apache.commons.mail.SimpleEmail;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.hibernate.cfg.Environment;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import static java.lang.System.getenv;

public class App {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    @Getter
    private final Config config;
    private Javalin javalin;
    private SessionFactory sessionFactory;

    private App(Config config) {
        this.config = config;
        algorithm = Algorithm.HMAC256(config.secret);
        verifier = JWT.require(algorithm).build();
    }

    public static void main(String[] args) {
        Config.builder()
                .secret(getenv("COSTSPLIT_SECRET"))
                .smtpHost(getenv("COSTSPLIT_SMTP_HOST"))
                .smtpPort(Integer.parseInt(getenv("COSTSPLIT_SMTP_PORT")))
                .senderMail(getenv("COSTSPLIT_SENDER_EMAIL"))
                .senderPassword(getenv("COSTSPLIT_SENDER_PASSWORD"))
                .port(Integer.parseInt(getenv("COSTSPLIT_PORT")))
                .isLocal(Boolean.parseBoolean(getenv("COSTSPLIT_LOCAL")))
                .build()
                .toApp()
                .start();
    }

    private static byte[] nextSalt() {
        byte[] buf = new byte[16];
        RANDOM.nextBytes(buf);
        return buf;
    }

    private static byte[] hashPassword(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var spec = new PBEKeySpec(password, salt, 65536, 256);
        var factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(spec).getEncoded();
    }

    public static void sendMail(String smtpHost, int smtpPort, String sender, String senderPassword, String receiver, String subject, String message) {
        var email = new SimpleEmail();
        email.setHostName(smtpHost);
        email.setSmtpPort(smtpPort);
        email.setAuthenticator(new DefaultAuthenticator(sender, senderPassword));
        try {
            email.setFrom(sender);
        } catch (EmailException e) {
            throw new InternalServerErrorResponse("Something went wrong with our email service");
        }
        email.setSubject(subject);
        try {
            email.addTo(receiver);
        } catch (EmailException e) {
            throw new BadRequestResponse("Invalid email");
        }
        try {
            email.setMsg(message);
        } catch (EmailException e) {
            throw new InternalServerErrorResponse("Couldn't generate mail message");
        }
        try {
            email.send();
        } catch (EmailException e) {
            throw new InternalServerErrorResponse("Couldn't send confirmation mail");
        }
    }

    public App start() {
        sessionFactory = new Configuration()
                .setProperty(Environment.HBM2DDL_AUTO, config.hbm2ddl)
                .setProperty(Environment.JAKARTA_JDBC_DRIVER, config.dbDriver)
                .setProperty(Environment.JAKARTA_JDBC_URL, config.dbUrl)
                .setProperty(Environment.JAKARTA_JDBC_USER, config.dbUser)
                .setProperty(Environment.JAKARTA_JDBC_PASSWORD, config.dbPassword)
                .addAnnotatedClass(Credential.class)
                .buildSessionFactory();
        javalin = Javalin.create(config -> config.jetty.modifyServer(server -> server.setStopTimeout(5_000)))
                .beforeMatched(ctx -> {
                    if (ctx.path().startsWith("/auth/"))
                        return;
                    var authHeader = ctx.header("Authentication");
                    if (authHeader == null || !authHeader.startsWith("Bearer "))
                        throw new UnauthorizedResponse();
                    var tok = authHeader.substring("Bearer ".length());
                    DecodedJWT jwt;
                    try {
                        jwt = verifier.verify(tok);
                    } catch (JWTVerificationException e) {
                        throw new ForbiddenResponse();
                    }
                    ctx.attribute("username", jwt.getClaim("username"));
                    ctx.attribute("email", jwt.getClaim("email"));
                    ctx.attribute("user-id", jwt.getClaim("user-id"));
                })
                .post(Request.CreateUser.ENDPOINT, ctx -> {
                    var body = ctx.bodyAsClass(Request.CreateUser.class);

                    // Create JWT data
                    var salt = nextSalt();
                    var saltString = Base64.getEncoder().encodeToString(salt);
                    var hash = Base64.getEncoder().encodeToString(hashPassword(body.password().toCharArray(), salt));
                    var url = "https://" + config.host + ":" + config.port + "/verify/"
                            + JWT.create()
                            .withClaim("username", body.name())
                            .withClaim("email", body.email())
                            .withClaim("salt", saltString)
                            .withClaim("password", hash)
                            .withExpiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
                            .sign(algorithm);

                    var subject = "Confirm your CostSplit account";
                    var message = "Hello " + body.name() + "!\n"
                            + "We are sending you this message so you can confirm the creation of your account.\n"
                            + "In order to verify please access the following link:\n"
                            + url;
                    sendMail(config.smtpHost, config.smtpPort, config.senderMail, config.senderPassword, body.email(), subject, message);
                })
                .get(Request.VerifyUser.ENDPOINT, ctx -> {
                    var tok = ctx.pathParam("token");
                    try {
                        var decodedTok = verifier.verify(tok);
                        sessionFactory.inTransaction(s -> {
                            s.persist(new Credential(
                                    decodedTok.getClaim("email").asString(),
                                    decodedTok.getClaim("username").asString(),
                                    decodedTok.getClaim("password").asString(),
                                    decodedTok.getClaim("salt").asString()));
                        });
                    } catch (JWTVerificationException e) {
                        throw new ForbiddenResponse("Invalid token");
                    }
                })
                .post(Request.Login.ENDPOINT, ctx -> {
                    var credentials = ctx.bodyAsClass(Request.Login.class);
                    var user = sessionFactory.fromTransaction(s -> s.find(Credential.class, credentials.email()));
                    if (user == null)
                        throw new UnauthorizedResponse("Email not in use");
                    var hash = hashPassword(credentials.password().toCharArray(), Base64.getDecoder().decode(user.getSalt()));
                    var hash64 = Base64.getEncoder().encodeToString(hash);
                    if (!hash64.equals(user.getHash())) {
                        throw new UnauthorizedResponse("Invalid credentials");
                    }
                    ctx.json(new Response.Login(JWT.create()
                            .withClaim("email", credentials.email())
                            .sign(algorithm)));
                })
                .start(config.host, config.port);
        return this;
    }

    public void stop() {
        javalin.stop();
    }

    @Builder
    @Accessors(fluent = true)
    @Getter
    public static class Config {
        @Builder.Default
        private final String host = "localhost";
        @Builder.Default
        private final int port = 8080;
        private final String secret;
        @Builder.Default
        private final boolean isLocal = false;
        private final String smtpHost;
        @Builder.Default
        private final int smtpPort = 25;
        private final String senderMail;
        private final String senderPassword;
        @Builder.Default
        private final String hbm2ddl = "none";
        private final String dbDriver;
        private final String dbUrl;
        private final String dbUser;
        private final String dbPassword;
        public App toApp() {
            return new App(this);
        }
    }
}
