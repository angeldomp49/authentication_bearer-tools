## Requirements ##

- java 17+
- MySQL as database
- PostgreSQL as database [link to docs](/docs/postgres.md)

## Dependency ##

__Maven dependency__

    <dependency>
        <groupId>org.makechtec.software</groupId>
        <artifactId>sql_support</artifactId>
        <version>2.1.0</version>
    </dependency>

__Gradle for groovy__

    implementation 'org.makechtec.software:sql_support:2.1.0'

__Gradle for kotlin__

    implementation ("org.makechtec.software:sql_support:2.1.0")

## Usage ##

__Example producing a Dto record__

    var connectionCredentials = new ConnectionInformation(
        "user",
        "pass",
        "host",
        "3306",
        "database"
    );

    var postgresEngine = new PostgresEngine<Dto>(connectionCredentials);

    ProducerByCall<Dto> producer =
            resultSet -> {

                Dto dto = null;
                while (resultSet.next()) {
                    dto = new Dto(
                            resultSet.getInt("id"),
                            resultSet.getString("name")
                    );
                }

                return dto;
            };

    try {
        var result =
                postgresEngine.isPrepared()
                        .queryString("CALL dto_by_id(?)")
                        .addParamAtPosition(1, 1, ParamType.TYPE_INTEGER)
                        .run(producer);
    } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
        e.printStackTrace();
    }

    assertFalse(dto.name().isEmpty());

Dto.java

    public record Dto(int id, String name) {}

## Pool ##

To use the connection pool functionality there is an example:

    var connectionInformation = new ConnectionInformation(
                "test",
                "test",
                "localhost",
                "3306",
                "test"
        );

    var pool = new ConnectionPool(4, new MySQLPooledConnectionCreator(connectionInformation));


    pool.boot();

    record Dto(int id, String name) {}

    var result =
        (new WithPoolEngine<Dto>(pool))
                        .queryString("SELECT * FROM test")
                        .run(resultSet -> {
                        resultSet.next();

                            return new Dto(resultSet.getInt("id"), resultSet.getString("name"));
                        });

For Postgres use same code as before but change the connection creator:

    var pool = new ConnectionPool(4, new PostgresPooledConnectionCreator(connectionInformation));

And that's it!!

### Releases history ###

3.0.0-beta Added connection pool functionality

2.1.0 Added PostgreSQL support

1.4.2 Fixing bug related to com.mysql.cj.jdbc.Driver class load

1.4.1 Fixing bug in types

1.4.0 Added more supported prepared statement types, in total they are:

- TYPE_STRING
- TYPE_INTEGER
- TYPE_FLOAT
- TYPE_LONG
- TYPE_BIG_DECIMAL
- TYPE_DOUBLE

1.3.2 Added ProducerByCall functionality