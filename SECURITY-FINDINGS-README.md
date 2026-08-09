# Security audit findings — summary

Target: `zulip/zulip` at `9b302b8b385c75b01f80f9573be0519c7ddbc4b4` (verified an
unmodified mirror of upstream `main` via `git ls-remote`).

All findings below were verified as unintended against Zulip's own help center,
API reference, in-code comments, or the surrounding code's conventions — except
where explicitly noted. No code changes were made; these are reports only.

| # | Finding | Component | Auth needed | Severity |
|---|---------|-----------|-------------|----------|
| 1 | [Spectators receive every user's custom profile fields](security-finding-spectator-profile-data.md) | `GET /json/users` | **None** | High (7.5) |
| 2 | [Guests receive all public-channel messages via event-queue `narrow`](security-finding-guest-event-queue-narrow.md) | Tornado event system | Guest account | High |
| 3 | [`history_public_to_subscribers` flippable without content access](security-findings-round-2.md#finding-a) | `PATCH /streams/{id}` | Channel admin | High |
| 4 | [Export "with consent" honors unsubscribed users' stale subscriptions](security-findings-round-2.md#finding-b) | `zerver/lib/export.py` | Realm admin | High |
| 5 | [DM forgery via mirroring client names](security-finding-mirror-dm-impersonation.md) | `POST /messages` | Any account | Medium–High (6.5) |

Finding 5 is reported with an explicit caveat: the mechanism is deliberate and
documented in the code. What is reported is the narrower gap between the stated
rationale and the capability actually granted.

## No Critical-severity finding

I did not find a Critical-severity vulnerability, and I have not relabelled any
of the above to claim one. The most severe is #1, at CVSS 7.5, notable because
it needs no account at all; it is not Critical because it requires the
organization to have web-public access enabled and exposes profile metadata
rather than message content or credentials.

## Areas audited and ruled out

Recorded so the negative results are reusable.

**Unauthenticated surface** — enumerated exhaustively (every
`allow_anonymous_user_web` route plus URL patterns registered outside
`rest_path`). `GET /json/messages` and `json_fetch_raw_message` gate on
`access_web_public_message`; `get_topics_backend` on `access_web_public_stream`;
file/thumbnail routes funnel through `validate_attachment_request`;
`avatar_by_email` refuses anonymous callers outright. Finding #1 is the only
hole found in this surface.

**Injection / rendering** — Markdown raw-HTML preprocessors and inline patterns
are disabled as "insecure"; `sanitize_url` uses a scheme allowlist; the code
fence language regex cannot escape its attribute; full-text search builds all
SQL through parameterized psycopg composables; `xhr_error_message` applies
`_.escape` before `.html()`; no `{{{ }}}` Handlebars usage outside the
`_html` convention.

**Authentication** — password reset, email change (both old and new cache keys
flushed), API-key regeneration (old key explicitly evicted, with a comment about
exactly that hazard), JWT (`verify_signature` with an explicit `algorithms`
list), the external-auth subdomain handoff (single-use 15s Redis token plus
subdomain match), SCIM bearer tokens (per-subdomain, constant-time), and
dev-login endpoints (gated on `settings.DEVELOPMENT`).

**Trusted-localhost paths** — nginx sets `REMOTE_ADDR` from
`$trusted_remote_addr`, not from a client-supplied header, and `/api/internal/`
is `allow 127.0.0.1; deny all`. `internal_api_view` additionally requires the
shared secret.

**Archive and import handling** — the web Slack import rejects any zip entry
containing a `..` component and enforces a strict filename regex plus a zip-bomb
size check; `import_uploads` resolves every source path with
`realpath`/`commonpath` containment and builds every destination path from
`sanitize_name` and a server-controlled integer realm ID.

**Export distribution** — tarballs are stored under a 144-bit
`secrets.token_urlsafe(18)` path segment, and `notify_realm_export` sends the
URL only to `realm.get_human_admin_users()`.

**Message access control** — `has_message_access`, `bulk_access_messages`,
`get_base_query_for_search`, and `ok_to_include_history` were traced against
each other; a wrongly-`True` `include_history` is always ANDed with a
restrictive recipient filter, and `add_new_user_history` filters on
`can_access_stream_history` so protected history holds on subscribe.

**Near-misses that were not bugs** — `bot_profile_cache_key` drops its
`realm_id` argument, but the underlying query is realm-independent by design and
documented as such; channel name-to-object resolution is identical in
`ok_to_include_history` and `by_channel`, so there is no lookup mismatch;
`getattr(settings, "STATUS_USED", 1)` in `confirmation/models.py` reads the
wrong settings module but the fallback happens to equal the correct value.

## Verification note

None of these were confirmed by running Zulip. The environment's egress proxy
returns 403 for apt and PPA repositories, so `tools/provision` cannot complete
and the Django test suite cannot run. Findings rest on code reading, with each
claim tied to a cited line and, where possible, to a contradicting piece of
Zulip's own documentation. The one piece of runtime verification that was
possible — executing `zerver/lib/narrow_predicate.py` against stubbed imports to
confirm the `is:unread` wildcard in finding #2 — is described in that report.
