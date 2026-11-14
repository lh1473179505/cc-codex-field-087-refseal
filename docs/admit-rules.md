# Admit rules

Reuse `load_json`. The update snapshot lists `old_oid`, `new_oid`, `ref`, `objects` (id → commit or tag), and `signatures` (id → `{key_id, mac}`). HMAC-SHA256 keys are in `--keys`. This lab does not run `git`.

A commit's signed bytes are `json.dumps({type,tree,parents,author,committer,message}, sort_keys=True, separators=(",", ":"))` (only those keys that exist). A tag object's signed bytes use `{type,object,object_type,tag,tagger,message}`. `mac` is lowercase hex.

The all-zero 40-character oid means "no previous tip". Reachability walks `parents` on commits and `object` on tags.

## Force push

If `ref` is in `policy.protected_refs` and `policy.allow_force` is false, and `old_oid` is not all-zero, the old tip must be reachable from the new tip. Otherwise `force_push`. Unprotected refs may rewind.

A missing or all-zero `new_oid`, or a new oid not in `objects`, is `broken_ref`.

## Introduced commits

Introduced objects are those reachable from `new_oid` but not from `old_oid` (an all-zero or missing old tip has an empty old set). Every introduced *commit* must have a signature that verifies with `--keys[key_id]`. Missing signature is `unsigned_commit`, unless the commit message contains a line with `signed-off-by:` (case-insensitive), in which case it is `trailer_only` — a trailer is not a substitute for a cryptographic signature. A present but invalid MAC or unknown `key_id` is `bad_signature`.

`policy.committer_keys` maps a lowercased email to a `key_id`. The committer email is taken from `Name <email>` or a bare email in `committer`. The signature's `key_id` must be that mapped key (`committer_mismatch`).

## Merge commits

A commit with two or more parents is a merge. After the merge itself verifies, each parent must either be in the old reachable set or have a valid signature (same committer mapping). Otherwise `unsigned_parent`.

## Tags

If `ref` starts with `refs/tags/` or the new object `type` is `tag`:

- An annotated tag's `tag` field must equal the name after `refs/tags/` (`tag_mismatch`).
- The tag object must be signed; the tagger email is checked against `committer_keys` like a committer.
- `object` must name a commit in the snapshot that itself has a valid mapped signature (`unsigned_tag_target` if the target is missing, not a commit, or unsigned).

A lightweight tag (the new object is a commit directly under `refs/tags/`) still requires that commit to be signed; a failure is `unsigned_tag_target` when the commit is unsigned, or the corresponding commit reason otherwise.

## Report and exit

Report: `decision`, `reason_codes`, `introduced` (sorted oids), `notes`. Stable order: `broken_ref`, `force_push`, `unsigned_commit`, `bad_signature`, `committer_mismatch`, `unsigned_parent`, `tag_mismatch`, `unsigned_tag_target`, `trailer_only`.

`allow` exits 0, `deny` exits 1, load failures exit 2.

## Public fixtures

`--policy fixtures/policy.json --keys fixtures/keys.json --update fixtures/updates/NAME.json`:

- `ok-ff.json` → allow
- `ok-merge.json` → allow
- `force-push.json` → deny `force_push`
- `unsigned-commit.json` → deny `unsigned_commit`
- `trailer-only.json` → deny `trailer_only`
- `bad-signature.json` → deny `bad_signature`
- `committer-mismatch.json` → deny `committer_mismatch`
- `unsigned-parent.json` → deny `unsigned_parent`
- `ok-tag.json` → allow
- `tag-mismatch.json` → deny `tag_mismatch`
