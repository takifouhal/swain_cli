# Using the SWAIN CLI

The SWAIN CLI helps you turn your API into SDKs that other developers can use.
Instead of hand-writing client code for every language, you point the CLI at
your API schema, choose the languages you want, and it writes SDK folders for
you.

The easiest way to use it is interactive mode. It walks you through the choices,
shows the command it built, and then generates the SDKs.

## Install

Install from PyPI:

```bash
python -m pip install swain_cli
```

Check that it is ready:

```bash
swain_cli --version
```

## Start with interactive mode

Run:

```bash
swain_cli interactive
```

The first thing it prints is:

```text
interactive SDK generation wizard
press Ctrl+C at any time to cancel
```

If you are not signed in yet, the CLI asks whether you want to sign in before
continuing. Then it asks for your username or email and password:

```text
no authentication token configured.
? Sign in before continuing? Yes
? Username or email
? Password
```

After sign-in, the wizard guides you through the SDK setup. The terminal UI may
look a little different depending on your shell, but the flow is:

```text
? Select Swain tenant ID
  Acme Workspace (#14)

? Select a project
  Customer API (#123)
  Internal Tools (#124)

? Select a connection
  #456 - production-db (postgres, schema=public)
  #457 - staging-db (postgres, schema=public)

? Output directory (sdks)

? Select target languages
  [x] python
  [x] typescript-axios (TypeScript + axios, default for 'typescript')
  [ ] typescript-fetch (TypeScript + Fetch API)
  [ ] javascript (plain JavaScript)
  [ ] dart (Dart)
  [ ] dart-dio (Dart/Flutter + Dio)
  [ ] go
  [ ] java
  [ ] csharp
  [ ] php
  [ ] ruby
  [ ] kotlin
  [ ] swift5 (Swift 5, default for 'swift')
  [ ] rust

? Use defaults for remaining generator settings? Yes
```

The tenant prompt only appears when the CLI needs you to choose or type a tenant
ID. If your token already points to one tenant, the CLI can use that and move on.

If there is only one project or one connection, the CLI does not make you pick
from a list. It prints what it detected and keeps going:

```text
Detected single project: Customer API (#123)
Detected single connection: production-db
```

Before it runs, it shows a preview. This is the useful part: you can see what
will be generated and the command you can reuse later.

```text
configuration preview
  swain base: https://api.swain.technology
  crudsql base: https://api.swain.technology/api/crud
  project: Customer API (#123)
  connection: #456 (production-db)
  dynamic swagger: https://api.example.com/api/dynamic_swagger
  tenant: 14
  output: sdks
  languages: python, typescript-axios
  patch base url: True
  parallel: 1
  engine: embedded
  skip validate: False
  verbose: False
  java options: -Xms2g -Xmx10g -XX:+UseG1GC
equivalent command: swain_cli gen --swain-tenant-id 14 --swain-project-id 123 --swain-connection-id 456 -o sdks -l python -l typescript-axios --java-opt -Xms2g --java-opt -Xmx10g --java-opt -XX:+UseG1GC
```

You do not need to memorize that command on the first run. The wizard is there
so you can choose in plain terms: the project, the API connection, the output
folder, and the SDK languages.

When generation finishes, each language gets its own folder:

```text
sdks/
  python/
  typescript-axios/
```

That is the main idea. Your API schema goes in, generated SDK code comes out.
The CLI handles the in-between work: finding the right schema, authenticating to
SWAIN, choosing the generator, and writing the SDKs into predictable folders.

## What the wizard is doing for you

The wizard is not a separate mode of generation. It is a friendly way to build a
normal `swain_cli gen` command.

It asks questions while the choices are still human:

```text
Which project?
Which connection?
Where should the SDKs go?
Which languages?
```

Then it turns those answers into a concrete command. That is useful because the
first run can be guided, while later runs can be repeated from a script, a
Makefile, or CI.

Use this when you want to preview the command without generating code:

```bash
swain_cli interactive --no-run
```

With `--no-run`, the wizard still shows the configuration preview and equivalent
command, then stops with:

```text
no-run mode enabled; generation not executed
```

## Signing in

For SWAIN-hosted APIs, sign in with:

```bash
swain_cli auth login
```

The CLI stores your access token locally so you do not need to paste it into
every command.

To check whether you are signed in:

```bash
swain_cli auth status
```

To sign out:

```bash
swain_cli auth logout
```

## Choosing languages

In interactive mode, select the languages from the prompt.

Common choices are:

```text
python
typescript-axios
typescript-fetch
javascript
dart
dart-dio
go
java
csharp
php
ruby
kotlin
swift5
rust
```

If you ask for more than one language, the CLI generates one SDK folder per
language.

## Using a local SWAIN API

If you are working against a local SWAIN backend, point the wizard at it:

```bash
swain_cli interactive --swain-base-url http://localhost:8084
```

The CLI will use that local backend while it discovers projects, connections,
and schemas.

## After the wizard: scripting mode

Once the wizard has helped you find the right project, connection, output
folder, and languages, you can run the same generation directly.

For a SWAIN connection:

```bash
swain_cli gen \
  --swain-project-id 123 \
  --swain-connection-id 456 \
  -l python \
  -l typescript-axios \
  -o ./sdks
```

If you want to see what would happen before writing files, add `--plan-only`:

```bash
swain_cli gen \
  --plan-only \
  --swain-project-id 123 \
  --swain-connection-id 456 \
  -l python \
  -o ./sdks
```

For automation, provide the auth token through the environment:

```bash
export SWAIN_CLI_AUTH_TOKEN="$SWAIN_TOKEN"
```

That is usually enough for CI: install the CLI, provide a token, then run the
same `swain_cli gen` command you tested locally.

## Quick command map

| Command | Use it when |
| --- | --- |
| `swain_cli interactive` | You want the CLI to guide you through SDK generation. |
| `swain_cli interactive --no-run` | You want to preview the generated command first. |
| `swain_cli auth login` | You need to sign in to SWAIN. |
| `swain_cli auth status` | You want to check your login state. |
| `swain_cli gen ...` | You already know the schema, project, connection, and languages. |
| `swain_cli gen --plan-only ...` | You want to preview a generation command without writing SDK files. |

In short: start with `swain_cli interactive`. Let it find the schema and build
the command. When you are ready to repeat the same generation later, use the
printed `swain_cli gen` command directly.
