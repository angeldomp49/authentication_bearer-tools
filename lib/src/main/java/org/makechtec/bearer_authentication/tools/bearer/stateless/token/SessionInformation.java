package org.makechtec.bearer_authentication.tools.bearer.stateless.token;

import org.json.JSONObject;

import java.util.Calendar;
import java.util.List;

public record SessionInformation(
        Calendar expirationDate,
        boolean isClosed,
        long userId,
        List<String> permissions,
        JSONObject claims
) {
}
