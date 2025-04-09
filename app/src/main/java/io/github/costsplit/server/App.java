package io.github.costsplit.server;

import com.auth0.jwt.JWT;
import io.github.costsplit.api.Request;
import io.javalin.Javalin;

import java.util.concurrent.TimeUnit;

public class App {
    private static final String SECRET = System.getenv("COSTSPLIT_SECRET");
    private static final Authernticator accountVerifier = new Authernticator(SECRET, TimeUnit.MINUTES.toMillis(30));
    private static final Authernticator requestVerifier = new Authernticator(SECRET, TimeUnit.DAYS.toMillis(1));

    public static void main(String[] args) {
        Javalin.create()
                .post("/auth/create", ctx -> {
                    var body = ctx.bodyAsClass(Request.CreateUser.class);
                    System.out.println("********* Create user *********");
                    System.out.println("Email   : " + body.email());
                    System.out.println("Password: " + body.password());
                    System.out.println("Name    : " + body.name());
                    System.out.println("URL     : https://localhost:8080/verify?token="
                            + accountVerifier.signToken(JWT.create()
                            .withSubject(body.name())
                            .withClaim("email", body.email())
                            .withClaim("password", body.password())));
                }).start(8080);
    }
}
