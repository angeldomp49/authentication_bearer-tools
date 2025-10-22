package org.makechtec.bearer_authentication.tools.bearer.stateless.token;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultJSONValidators.JSON_NOT_EMPTY;

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
    
    @Test
    void generateJWTWithNonEmptyHeaderAndNonEmptyPayload() {

        var generator = new JWTTokenGenerator();

        var header = ObjectLeafBuilder.builder()
                .put("alg", "HS256")
                .put("typ", "JWT")
                .build();

        var payload = ObjectLeafBuilder.builder()
                .put("sub", "1234567890")
                .put("name", "John Doe")
                .put("iat", 1516239022)
                .build();

        var token = generator.generateJWT("thisIsASecretKeyWith32Characters!", header, payload);

        assertTrue(generator.isValidSignature(token, "thisIsASecretKeyWith32Characters!"));

        var reformedHeader = generator.getJWTHeader(token);
        assertEquals("HS256", reformedHeader.getString("alg"));
        assertEquals("JWT", reformedHeader.getString("typ"));

        var reformedPayload = generator.getJWTPayload(token);
        assertEquals("1234567890", reformedPayload.getString("sub"));
        assertEquals("John Doe", reformedPayload.getString("name"));
        assertEquals(1516239022, reformedPayload.getInt("iat"));
    }

    @Test
    void generateJWTWithEmptyHeaderThrowsException() {

        var generator = new JWTTokenGenerator();

        var emptyHeader = ObjectLeafBuilder.builder().build();

        var payload = ObjectLeafBuilder.builder()
                .put("sub", "1234567890")
                .build();

        var exception = assertThrows(IllegalArgumentException.class, () -> {
            generator.generateJWT("thisIsASecretKeyWith32Characters!", emptyHeader, payload);
        });

        assertTrue(exception.getMessage().contains("Invalid JSON header"));
    }

    @Test
    void generateJWTWithEmptyPayloadThrowsException() {

        var generator = new JWTTokenGenerator();

        var header = ObjectLeafBuilder.builder()
                .put("alg", "HS256")
                .build();

        var emptyPayload = ObjectLeafBuilder.builder().build();

        var exception = assertThrows(IllegalArgumentException.class, () -> {
            generator.generateJWT("thisIsASecretKeyWith32Characters!", header, emptyPayload);
        });

        assertTrue(exception.getMessage().contains("Invalid JSON payload"));
    }

    @Test
    void generateJWTWithEmptyHeaderAndEmptyPayloadThrowsException() {

        var generator = new JWTTokenGenerator();

        var emptyHeader = ObjectLeafBuilder.builder().build();
        var emptyPayload = ObjectLeafBuilder.builder().build();

        var exception = assertThrows(IllegalArgumentException.class, () -> {
            generator.generateJWT("thisIsASecretKeyWith32Characters!", emptyHeader, emptyPayload);
        });

        assertTrue(exception.getMessage().contains("Invalid JSON"));
    }
    
    @Test
    void checkJson(){
        var header = ObjectLeafBuilder.builder()
                .put("alg", "HS256")
                .build();
        
        System.out.println(header.getLeafValue());
        
        var result = JSON_NOT_EMPTY.validate(header.getLeafValue());
        
        assertTrue(result);
    }
}

