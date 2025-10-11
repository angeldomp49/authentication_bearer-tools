## Requirements ##

- Java 17+

___

## Dependency ##

### Maven Dependency ###

    <dependency>
        <groupId>org.makechtec.software</groupId>
        <artifactId>json_tree</artifactId>
        <version>3.0.0</version>
    </dependency>

### Gradle for groovy ###

    implementation 'org.makechtec.software:json_tree:3.0.0'

### Gradle for kotlin ###

    implementation ("org.makechtec.software:json_tree:3.0.0")

___

## Usage ##

Examples:

    var item =
                ObjectLeaftBuilder.builder()
                        .put("id", 1)
                        .put("name", "Jhon")
                        .put("hasPassed", false)
                        .build();

        var result =
                ArrayLeafBuilder.builder()
                        .add(item)
                        .add(item)
                        .build()
                        .getLeafValue();

        var obj = new JSONArray(result);

        assertEquals("Jhon", obj.getJSONObject(0).getString("name"));
        assertEquals(1, obj.getJSONObject(0).getInt("id"));
        assertFalse(obj.getJSONObject(0).getBoolean("hasPassed"));

### Validation ###