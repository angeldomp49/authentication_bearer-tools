# Project Documentation #

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

Your task is to create a detailed documentation for the project, you are a java developer specialized in cryptography.

## Context ##

Please read the documentation of the project if it exists and follow to the libraries links to make sure you
understand how the project works and why are used these libraries.

Please read the existing tests to understand the main features of the project.

Please keep in mind the following points:

- This library is designed to facilitate the token generation.
- This library is designed to provide stateless helper function, so far, probably in the future it will include interfaces
  to connect to external persistance systems, but not using specific implementations.
- The documentation must be translated to english, spanish and french.

## Task ##

You have to follow the structure below to create the documentation:

docs/
 en/
  README.md
  ...
 es/
  README.md
  ...
 fr/
  README.md
  ...
