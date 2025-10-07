# Copilot Instructions (Shared Context)

## Programming Language
- Java
- Don't use Kotlin for source code, just for configuration files if needed.
- Use Java 17.

## Comments

- Don't use comments inside the code.
- Don't add explanations.

## Code Quality

- Ensure the code is self-explanatory.
- Ensure the code follows the `Clean Code` principles.
- Ensure the code follows the `SOLID` principles.
- Ensure the code follows the `Clean Architecture` principles.
- Spend more code in order to make the code more readable.
- Ensure the code is well formatted.
- Ensure you use guard clauses to reduce nesting over if-else statements.
- Ensure you use the "Objects.isNull" and "Objects.nonNull" methods to check for null values.
- Ensure you don't use inheritance at all, when you need to share code between classes use composition instead.
- Ensure don't use reflections in the code or use any library that uses reflections, unless it's explicitly indicated in the prompt.


## Documentation

- For each new functionality added to the codebase, add the necessary documentation.
- Ensure the documentation is centered in the main functionalities, not specifically 
  in a specific package, class or method.
- Ensure the documentation have at least one example of usage for the added functionality.
- Ensure the documentation is in Markdown format.
- Ensure the documentation is in English.
- Ensure the documentation has translations to Spanish and French.
- Ensure the documentation is in a `docs` folder at the root of the project.


## Specific configurations for this project ##

### Dependencies ###

This project doesn't use any dependency manager, nor spring boot or any other.