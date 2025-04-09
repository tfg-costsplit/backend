package io.github.costsplit.app;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.github.costsplit.api.Request;
import io.javalin.Javalin;
import io.javalin.http.ForbiddenResponse;
import io.javalin.http.UnauthorizedResponse;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

public class App {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String DOMAIN = "localhost";
    private static final String SECRET = System.getenv("COSTSPLIT_SECRET");
    private static final Algorithm algorithm = Algorithm.HMAC256(SECRET);
    private static final JWTVerifier verifier = JWT.require(algorithm).build();

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

    public static Javalin start() {
        return Javalin.create()
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
                    var salt = nextSalt();
                    var saltString = Base64.getEncoder().encodeToString(salt);
                    var hash = Base64.getEncoder().encodeToString(hashPassword(body.password().toCharArray(), salt));
                    System.out.println("********* Create user *********");
                    System.out.println("Name    : " + body.name());
                    System.out.println("Email   : " + body.email());
                    System.out.println("Salt    : " + saltString);
                    System.out.println("Password: " + hash);
                    System.out.println("URL     : https://" + DOMAIN + "/verify?token="
                            + JWT.create()
                            .withClaim("username", body.name())
                            .withClaim("email", body.email())
                            .withClaim("salt", saltString)
                            .withClaim("password", hash)
                            .withExpiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
                            .sign(algorithm));
                }).start(8080);
    }

    public static void main(String[] args) {
        start();
    }
}
