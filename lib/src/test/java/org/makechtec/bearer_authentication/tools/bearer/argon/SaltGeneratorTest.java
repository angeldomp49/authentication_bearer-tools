package org.makechtec.bearer_authentication.tools.bearer.argon;

import org.junit.jupiter.api.Test;

class SaltGeneratorTest {

    @Test
    void formatSaltToString() {
        var saltGenerator = new SaltGenerator();

        var result = saltGenerator.formatSaltToString(saltGenerator.generate());

        System.out.println(result);
    }
}