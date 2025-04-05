package org.makechtec.bearer_authentication.tools.bearer.token;

import org.makechtec.software.json_tree.builders.ArrayStringLeafBuilder;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;


public class JWTTokenHandler {
    
    public String createTokenForSession(SessionInformation session, String secretKey) {

        var signaturePrinter = new SignaturePrinter(secretKey);
        var permissionsSet = ArrayStringLeafBuilder.builder();

        session.permissions().forEach(permissionsSet::add);

        return TokenBuilder.builder(signaturePrinter)
                .header(
                        ObjectLeafBuilder.builder()
                                .put("alg", "SHA256")
                                .put("typ", "jwt")
                                .build()
                )
                .payload(
                        ObjectLeafBuilder.builder()
                                .put("exp", session.expirationDate().getTimeInMillis())
                                .put("uid", session.userId())
                                .put("isClosed", session.isClosed())
                                .put("permissions", permissionsSet.build())
                                .build()
                )
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

}
