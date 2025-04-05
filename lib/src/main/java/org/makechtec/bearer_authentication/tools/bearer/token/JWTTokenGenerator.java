package org.makechtec.bearer_authentication.tools.bearer.token;

import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;

public class JWTTokenGenerator {
    
    public String generateJWT(String secretKey, ObjectLeaf jsonHeader, ObjectLeaf jsonPayload) {
        var signaturePrinter = new SignaturePrinter(secretKey);

        return TokenBuilder.builder(signaturePrinter)
                .header(jsonHeader)
                .payload(jsonPayload)
                .sign()
                .build();
    }
    
}
