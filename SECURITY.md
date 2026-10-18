# Security policy

## Supported versions

Until the first stable release, security fixes are provided on the latest
release only.

## Reporting a vulnerability in noirspect

Please use GitHub's **Security** tab and select **Report a vulnerability** to
start a private advisory. Include the affected version, a reproduction with
synthetic circuits, impact, and a suggested fix if available.

Maintainers should acknowledge complete reports within seven days and
coordinate a fix and disclosure timeline with the reporter.

In scope: a missed finding that a documented rule claims to cover, unsafe
file handling, and any network access beyond the dependency fetches nargo
itself performs for `Nargo.toml` git dependencies.

## Bugs that noirspect finds in other projects

A finding in third-party code may be a real soundness vulnerability. Report it
privately to that project's maintainers first, using their security policy,
and only write about it publicly after a fix ships. Do not add unfixed
third-party bugs to this repository's test corpus.

## Data handling

noirspect reads the analyzed workspace and its dependencies and writes only
the report you ask for. It does not execute circuits or send data anywhere.
Compile-time (`comptime`) code in the analyzed workspace runs inside the
Noir compiler's interpreter, as it does with `nargo check`.
