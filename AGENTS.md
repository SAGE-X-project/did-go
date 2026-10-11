# Commit and pull request rules

- Use Conventional Commits: a concise English `type: description` describing the actual behavior.
- Write all commit messages and pull request titles and descriptions in English.
- Never include emojis or co-author attribution, including Co-authored-by trailers, in human/agent-authored commits and pull requests. Dependabot-authored changes are the sole exception.
- Keep the content focused on the essential change. Describe behavior explicitly; do not use development phase names or task identifiers.
- Apply these rules to squash commit titles and bodies as well.
- Merge pull requests only with squash merge. After merging, delete the work branch locally and remotely, then update local main to match remote main.

# Pull request review requests

- Never request a code review from SAGE Core Team (`SAGE-X-project/sage-core-dev`), manually or automatically, for any pull request.
- Check CODEOWNERS, Dependabot and workflow assignments before PR creation or readiness. Do not add this team as a reviewer or send it review requests.

# Library scope

- did-go implements W3C DID Core 1.0 and DID 1.1 side by side. Cite the dated specification text that each behavior follows.
- The root module must not depend on SAGE. SAGE-specific code lives in its own Go module.
- Never put private keys, trust decisions or key custody into the library.
- Every validation rule needs a positive and a negative test. Keep statement coverage at or above 90%.
