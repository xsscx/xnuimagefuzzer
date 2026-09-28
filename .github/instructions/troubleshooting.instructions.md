# Troubleshooting

If clean generation produces no files, verify the native helper exists and set
XNU_IMAGE_OUTPUT_DIR to a writable directory. No arguments and --clean should
behave identically.

If corpus construction reports a nonempty ICC-free source, the input already
contains a binary profile. Regenerate clean sources; do not silently strip or
relabel the input.

If an exact-ICC case fails, inspect its manifest entry and direct container
payload. A framework property or filename is not proof of embedded bytes.

For a macOS round trip, dropped, rewritten, substituted_system_profile, and
rejected are measured outcomes rather than script failures. Requested and
observed evidence must be retained.

The builder refuses to replace a nonempty directory unless its manifest
identifies an xnuimagefuzzer QA corpus. Choose a new path instead of weakening
this guard.
