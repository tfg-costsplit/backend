package io.github.costsplit.server;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

public record Authernticator(String secret, long expirationTime) {
    public String signToken(JWTCreator.Builder builder) {
        var now = System.currentTimeMillis();
        return builder.withIssuedAt(new Date(now))
                .withIssuedAt(new Date(now + expirationTime))
                .sign(Algorithm.HMAC256(secret));
    }

    public DecodedJWT verifyToken(String tok) throws JWTVerificationException {
        return JWT.require(Algorithm.HMAC256(secret)).build().verify(tok);
    }
}
