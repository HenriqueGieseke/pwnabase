# Repository checks (Linux)

Run `./scripts/check` from the checkout to check current working files. It uses
existing local tools and stops on the first failure with a nonzero exit status.
The required stages are whitespace (staged and unstaged), Python compilation,
ordinary Python tests, and frontend result-reader tests. No full Nuxt build or
dependency installation is performed.

Use `./scripts/check --real-tools` explicitly at a recovery integration milestone.
This enables the existing synthetic Hashcat/extractor integrations, which use
small temporary wordlists and select CPU. Ordinary checks force those tests off,
even if the shell has `RUN_REAL_TOOLS=1`. The explicit mode requires installed
Hashcat/hcxtools; it never runs against the real capture directory.

Requirements: Linux, Python 3.10+, Git, a compatible Node version according to the
frontend manifest, and writable temporary storage. An existing compatible
project-local Node is preferred; otherwise use a compatible Node on PATH.
The selected executable is shared by frontend checks and Python tests launching
Node. Missing tools produce an error rather than a download or silent skip.

Compilation caches, temporary runtime selection and test outputs stay outside
the checkout. No formatting, staging, stashing or automatic fixing occurs. On
failure or interruption, later stages are not run and temporary state is cleaned.
Cancellation terminates the check process group, including descendants that
outlive its leader.

The check runner's own tests use small temporary fixture repositories containing
only a controlled test workload; they do not recursively run this entire suite.
Staged-snapshot mode and hook activation follow in tickets 9 and 10.
