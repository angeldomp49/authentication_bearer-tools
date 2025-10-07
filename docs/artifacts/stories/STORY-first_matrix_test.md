
# First Matrix Test #

Based on the following information please create a detailed specification which will serve
as input for Claude Sonnet 4 in Agent mode for Copilot to implement the feature.

## Structure ##

Add the following section first:

```markdown
Status: draft
Owner: @angeldomp49
Source Model: Claude Opus 4.1 (Ask Mode)
Last Sync: %%timestamp%%

```

### Project Information ###

- **Project Name**: Bearer Authentication Tools

## Feature information ##

### Role ###

Your task is to create robust integration tests, preferred by using Concordion to create html files and
embed executable logic in them, you have to take the role as a QA tester specialized in cryptography.


## Context ##

Please read the documentation of the project if it exists and follow to the libraries links to make sure you
understand how the project works and why are used these libraries.

Please read the existing tests to understand the main features of the project.

## Task ##

You have to add the Concordion and all the missing testing libraries you will need to create the tests.

You will mock as fewer components as possible, like the libraries or databases calls.

You have to read the tests to understand the main features of the project as well as the most
important components.

You have to read the external-references directory to understand the usage of the libraries.

You have to create a test matrix in mark-down format for to test all cases you identify for all the components.

You have to include the jacoco report dependency to be able to measure the code coverage.

You can use the src/test/java or src/test/resources folders with full freedom to create any utility
classes or files you need to create the tests.

You have to make sure the test code is clean and follows the best practices added to the "clean code",
"clean architecture", "refactoring" as well as the SOLID principles.

If the tests fails, you have to fix the code in order to make the tests pass.

Every test must have at least one validation assertion besides the output or any internal
state or method execution.

Make sure the concordion execution reports are generated in the expected folder after
the test execution.

## Conditions to Stop ##

You will stop when you created and run successfully all the tests for all the components.
