package org.makechtec.bearer_authentication.tools.bearer.stateless.token;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWTTokenGeneratorTest {

    @Test
    void getJWTPayload() {

        var generator = new JWTTokenGenerator();

        var header = ObjectLeafBuilder.builder()
                .put("alg", "HS256")
                .build();

        var payload = ObjectLeafBuilder.builder()
                .put("kty", "RSA")
                .build();

        var token = generator.generateJWT("secretKey", header, payload);
        var reformedHeader = generator.getJWTHeader(token);
        var expectedHeader = new JSONObject("""
                {"alg":"HS256"}
                """);
        var reformedPayload = generator.getJWTPayload(token);
        var expectedPayload = new JSONObject("""
                {"kty":"RSA"}
                """);

        assertTrue(generator.isValidSignature(token, "secretKey"));


        assertEquals(expectedHeader.getString("alg"), reformedHeader.getString("alg"));
        assertEquals(expectedPayload.getString("kty"), reformedPayload.getString("kty"));

    }
}