package org.makechtec.bearer_authentication.tools.bearer.stateless.token;

import org.json.JSONObject;
import org.makechtec.software.json_tree.ObjectLeaf;

import java.util.Base64;

public class JWTTokenGenerator {

    public String generateJWT(String secretKey, ObjectLeaf jsonHeader, ObjectLeaf jsonPayload) {
        var signaturePrinter = new SignaturePrinter(secretKey);

        return TokenBuilder.builder(signaturePrinter)
                .header(jsonHeader)
                .payload(jsonPayload)
                .sign()
                .build();
    }

    public boolean isValidSignature(String token, String secretKey) {

        var signaturePrinter = new SignaturePrinter(secretKey);
        var components = token.split("\\.");

        var message = components[0] + '.' + components[1];

        var reformedSignature = signaturePrinter.sign(message);
        var reformedToken = components[0] + '.' + components[1] + '.' + reformedSignature;

        return reformedToken.equals(token);
    }
    
    public JSONObject getJWTPayload(String token) {
        var components = token.split("\\.");
        return new JSONObject(Base64.getDecoder().decode(components[1]));
    }

    public JSONObject getJWTHeader(String token) {
        var components = token.split("\\.");
        return new JSONObject(Base64.getDecoder().decode(components[0]));
    }

}
