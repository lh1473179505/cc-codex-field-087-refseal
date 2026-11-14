# refseal

A git-ref admission tool for a snapshot of commits, tags, and HMAC signatures.

`python -m refseal inspect --update fixtures/updates/ok-ff.json` already prints the ref and oids. `admit` is still a stub.

Standard library only. No Docker, no real git hooks.
