# Two further security findings

**Affected commit:** `9b302b8b385c75b01f80f9573be0519c7ddbc4b4` (`main`, unmodified
mirror of `zulip/zulip`)

Both findings below are private-channel confidentiality bypasses, verified as
unintended against the help center, the in-code comments, and the surrounding
code's own conventions.

| # | Component | Class | Severity |
|---|-----------|-------|----------|
| A | `zerver/views/streams.py` — `PATCH /streams/{id}` | Missing permission check | High |
| B | `zerver/lib/export.py` — export with consent | Stale-state authorization | High |

---

# Finding A: `history_public_to_subscribers` can be flipped without content access

**Component:** `zerver/views/streams.py:290-423` (`update_stream_backend`)
**Class:** Broken access control — content-access-affecting setting gated only by
metadata access

## Summary

Zulip separates *metadata access* to a channel (see its name, description,
subscribers, settings) from *content access* (read its messages). Changing a
setting that affects who can read a channel's content is supposed to require
content access — `update_stream_backend` enforces exactly that for
`is_private`, and for the `can_add_subscribers_group` / `can_subscribe_group`
settings.

`history_public_to_subscribers` is not gated. A channel administrator (or
organization administrator) who is **not** subscribed to a private channel, and
who therefore cannot read a single message in it, can flip that channel from
**protected history** to **shared history**. Every subscriber — including
members added long after the sensitive discussion happened — immediately gains
read access to the channel's entire back history.

The attacker does not gain read access themselves; the impact is the
unauthorized, irreversible disclosure of a private channel's archive to a wider
audience than the organization chose.

## Why this is not intended behavior

1. **The sibling setting in the same function is gated, with a comment saying
   why.** `zerver/views/streams.py:372-381`:

   ```python
   if is_private is not None and not user_has_content_access(
       user_profile, stream, user_group_membership_details,
       is_subscribed=sub is not None,
   ):
       raise JsonableError(_("Channel content access is required."))
       # In addition to channel administration permissions, changing
       # public/private status for channels requires content access
       # to the channel.
   ```

   Three lines further down (`zerver/views/streams.py:412-423`),
   `history_public_to_subscribers` reaches `do_change_stream_permission()`
   through the same call with no such check:

   ```python
   if (
       is_private is not None
       or is_web_public is not None
       or history_public_to_subscribers is not None   # <-- unguarded path
   ):
       do_change_stream_permission(
           stream,
           invite_only=proposed_is_private,
           history_public_to_subscribers=proposed_history_public_to_subscribers,
           is_web_public=proposed_is_web_public,
           acting_user=user_profile,
       )
   ```

   `do_change_stream_permission` (`zerver/actions/streams.py:1280`) performs no
   authorization of its own.

2. **The help center states the rule the code fails to enforce.**
   `starlight_help/src/content/include/_ChannelAdminPermissions.mdx` — channel
   and organization administrators who aren't subscribed to a private channel
   "cannot gain access to its content, **or grant access to others**, unless
   specifically permitted to do so." They may "modify settings **that do not
   affect content access** (e.g., who can post or message retention policy)",
   while "**Modifying settings that affect content access**" requires specific
   permissions.

3. **The help center defines this exact setting as controlling content
   access.** `starlight_help/src/content/docs/channel-permissions.mdx:57-61`:

   > * In private channels with **shared history**, new subscribers can access
   >   the channel's full message history.
   > * In private channels with **protected history**, new subscribers can only
   >   see messages sent after they join.

4. **The code's own access check treats it as content-determining.**
   `has_message_access` (`zerver/lib/message.py:606-618`) branches on
   `stream.is_history_public_to_subscribers()`: with protected history a
   subscriber additionally needs a `UserMessage` row; with shared history the
   subscription alone suffices.

5. **There is no test for it.** `zerver/tests/test_channel_permissions.py`
   (`test_permission_for_updating_privacy_of_unsubscribed_private_channel`) and
   `zerver/tests/test_subs.py:246` assert `"Channel content access is required."`
   for `invite_only` and `is_web_public` only. No test covers
   `history_public_to_subscribers`, which is what let the gap survive.

## Steps to reproduce

Setup: private channel `leadership` with **protected history**
(`history_public_to_subscribers=false`), containing sensitive back history.
Alice is **not** subscribed and is in the channel's
`can_administer_channel_group`. Bob is a subscriber who joined recently, so he
can only see messages sent since he joined.

1. **Confirm Alice has no content access** (control case — correctly denied
   today):

   ```bash
   # Reading the channel fails:
   curl -sSG https://ZULIP.EXAMPLE.COM/api/v1/messages \
     -u alice@example.com:ALICE_API_KEY \
     --data-urlencode 'anchor=newest' --data-urlencode 'num_before=10' \
     --data-urlencode 'num_after=0' \
     --data-urlencode 'narrow=[["channel","leadership"]]'

   # And so does making it public:
   curl -sSX PATCH https://ZULIP.EXAMPLE.COM/api/v1/streams/CHANNEL_ID \
     -u alice@example.com:ALICE_API_KEY \
     --data-urlencode 'is_private=false'
   # => {"result":"error","msg":"Channel content access is required."}
   ```

2. **Confirm Bob cannot see the old messages** — as Bob, fetch the channel and
   note the oldest message ID he can retrieve.

3. **As Alice, flip the history setting** (omitting `is_private` entirely):

   ```bash
   curl -sSX PATCH https://ZULIP.EXAMPLE.COM/api/v1/streams/CHANNEL_ID \
     -u alice@example.com:ALICE_API_KEY \
     --data-urlencode 'history_public_to_subscribers=true'
   ```

   **Expected:** `"Channel content access is required."`, as for `is_private`.
   **Actual:** `{"result":"success"}`.

4. **As Bob, re-fetch the channel.** He now receives the channel's entire
   history, including everything sent before he joined.

The same works for an organization administrator who is not subscribed to the
private channel — `access_stream_for_delete_or_update_requiring_metadata_access`
(`zerver/lib/streams.py:857-860`) returns early for realm admins, and step 1
shows they are otherwise correctly blocked from widening access.

## Impact

- Retroactive disclosure of a private channel's complete archive to every
  current and future subscriber, performed by someone who cannot read the
  channel.
- Defeats the "protected history" guarantee, whose purpose is precisely to keep
  earlier discussion from new joiners.
- Irreversible: setting the flag back does not un-read the messages.
- The attacker does **not** gain read access themselves — self-subscription
  still correctly requires content access
  (`filter_stream_authorization_for_adding_subscribers`,
  `zerver/lib/streams.py:1521`), so this is a disclosure-to-others bug, not
  privilege escalation for the actor.

Rough CVSS v3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` (7.1).

## Suggested fix

Extend the existing gate to cover the setting:

```python
if (
    is_private is not None or history_public_to_subscribers is not None
) and not user_has_content_access(
    user_profile, stream, user_group_membership_details, is_subscribed=sub is not None
):
    raise JsonableError(_("Channel content access is required."))
```

and add `history_public_to_subscribers` to the
`test_permission_for_updating_privacy_of_unsubscribed_private_channel` matrix so
the three privacy-affecting fields are covered uniformly.

---

# Finding B: export "with consent" uses unsubscribed users' stale subscriptions

**Component:** `zerver/lib/export.py:1911-1918`
(`export_partial_message_files`)
**Class:** Broken access control — authorization decision made on stale state

## Summary

`Subscription` rows are never deleted; unsubscribing sets `active=False`
(`zerver/models/streams.py:381-385`). Every access check in the codebase filters
on `active=True` accordingly. The realm-export "public and private data (with
consent)" path does not.

As a result, a private channel is treated as consented-to if any consenting user
was **ever** subscribed to it — even if they left, or were removed, years ago.
The export then contains that channel's complete message history, including
every message sent after the consenting user lost access.

Because a realm administrator can set `allow_private_data_export` on their own
account, this is directly self-serving: an administrator who was once in a
private channel and has since left it can extract everything said in that
channel since their departure.

## Why this is not intended behavior

1. **The help center defines the boundary in the present tense.**
   `starlight_help/src/content/docs/export-your-organization.mdx:29-36` —
   "**Public and private data (with consent)**: … plus all the private channel
   messages and direct messages that members who have allowed administrators to
   export their private data **can access**."

   A user who has unsubscribed from a private channel cannot access it:
   `has_channel_content_access_helper` (`zerver/lib/message.py:537-541`) requires
   `Subscription.objects.filter(..., active=True)`.

2. **The code's own comment states the same rule.**
   `zerver/lib/export.py:1949-1951`: "Export with member consent requires some
   careful handling to make sure we only include messages that a consenting user
   can access."

3. **Every comparable query in the codebase filters `active=True`** — e.g.
   `check_can_access_user` (`zerver/lib/users.py:766-778`),
   `get_inaccessible_users_queryset` (`zerver/lib/users.py:790-800`),
   `has_channel_content_access_helper`, `bulk_access_stream_messages_query`.
   `zerver/lib/export.py` contains no `active=True` anywhere; it is the outlier.

4. **The adjacent branch does bound by real access.** For protected-history
   channels (`zerver/lib/export.py:1954-1971`) the export additionally requires
   `Exists(UserMessage.objects.filter(user_profile_id__in=consented_user_ids, ...))`
   — deliberate care to include only messages a consenting user actually
   received. The shared-history branch has no such bound and relies entirely on
   the unfiltered subscription lookup.

5. **No test covers it.** `zerver/tests/test_import_export.py` contains no
   unsubscribe scenario for consent exports.

## The defect

`zerver/lib/export.py:1911-1918`:

```python
consented_recipient_ids = Subscription.objects.filter(
    user_profile_id__in=consented_user_ids
).values_list("recipient_id", flat=True)          # <-- no active=True

recipient_ids_set = (set(public_stream_recipient_ids) | set(consented_recipient_ids)) - set(
    streams_with_protected_history_recipient_ids
)
recipient_ids_for_us = get_ids(response["zerver_recipient"]) & recipient_ids_set
```

`recipient_ids_for_us` then feeds the unbounded message query
(`zerver/lib/export.py:1940-1948`):

```python
messages_we_received = Message.objects.filter(
    realm_id=realm.id,
    sender__in=ids_of_our_possible_senders,
    recipient__in=recipient_ids_for_us,
)
```

There is no date bound and no per-message `UserMessage` check, so *all* messages
ever sent to that channel are exported. `response["zerver_recipient"]` includes
every channel in the realm (`zerver/lib/export.py:1087-1102` exports
`zerver_stream` with `include_rows="realm_id__in"`), so the intersection does not
constrain anything.

The protected-history branch is affected by the same root cause, more mildly: a
stale subscriber's `UserMessage` rows survive unsubscription, so messages they
received while subscribed are exported even though
`has_message_access` no longer grants them access.

## Steps to reproduce

Setup: private channel `board` with **shared history**
(`history_public_to_subscribers=true`, a standard option — see
`_ChannelPrivacyTypes.mdx`, "You can choose whether new subscribers can see
messages sent before they were subscribed"). Mallory is an organization
administrator who was subscribed to `board` at some point and has since left it.

1. **Confirm Mallory currently has no access:**

   ```bash
   curl -sSG https://ZULIP.EXAMPLE.COM/api/v1/messages \
     -u mallory@example.com:MALLORY_API_KEY \
     --data-urlencode 'anchor=newest' --data-urlencode 'num_before=50' \
     --data-urlencode 'num_after=0' \
     --data-urlencode 'narrow=[["channel","board"]]'
   ```

   Returns nothing from `board`. Her `Subscription` row still exists with
   `active=False`.

2. **Have the remaining members post to `board`** — these are messages Mallory
   never received and cannot read.

3. **Mallory marks herself as consenting:**

   ```bash
   curl -sSX PATCH https://ZULIP.EXAMPLE.COM/api/v1/settings \
     -u mallory@example.com:MALLORY_API_KEY \
     --data-urlencode 'allow_private_data_export=true'
   ```

4. **Mallory starts an export with consent** and downloads it when ready:

   ```bash
   curl -sSX POST https://ZULIP.EXAMPLE.COM/api/v1/export/realm \
     -u mallory@example.com:MALLORY_API_KEY \
     --data-urlencode 'export_type=export_full_with_consent'

   curl -sSG https://ZULIP.EXAMPLE.COM/api/v1/export/realm \
     -u mallory@example.com:MALLORY_API_KEY
   ```

5. **Inspect `messages-000001.json` in the tarball.**
   **Expected:** no messages whose `recipient` is `board`, since no consenting
   user can access that channel.
   **Actual:** every message ever sent to `board` is present, including those
   from step 2.

The same works without Mallory being the one who left: any consenting user in
the organization with a stale `Subscription` row for a private channel is enough
to pull that whole channel into any administrator's consent export.

## Impact

- An organization administrator obtains the full contents of private channels
  that no consenting user can currently access — the precise thing the
  "with consent" export type exists to prevent. (The "all public and private
  data" export, which does grant this, is owner-only and gated on
  `realm.owner_full_content_access`; see `zerver/views/realm_export.py:39-51`.)
- Self-serving for any administrator who ever belonged to the target channel,
  including one removed from it for cause.
- Silent: the export succeeds normally and nothing signals the over-collection.

Rough CVSS v3.1: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` (6.5); higher in practice
because the export is the designated compliance-safe path and is trusted to
respect consent.

## Suggested fix

```python
consented_recipient_ids = Subscription.objects.filter(
    user_profile_id__in=consented_user_ids, active=True
).values_list("recipient_id", flat=True)
```

Also constrain the protected-history branch so that a stale subscriber's
lingering `UserMessage` rows don't pull in messages they can no longer access,
and add a regression test that unsubscribes a consenting user from a private
channel, posts more messages, and asserts the channel is absent from the export.

---

# Lower-severity notes from the same sweep

Reported for completeness; neither is independently exploitable at the level
above.

1. **`default_all_public_streams` bypasses the guest firehose check.**
   `events_register_backend` (`zerver/views/events_register.py:71-75`) and
   `get_events_backend` (`zerver/tornado/views.py:237`) test
   `if all_public_streams and not user_profile.can_access_public_streams()`
   *before* falling back to `user_profile.default_all_public_streams`
   (`_default_all_public_streams`, `zerver/views/events_register.py:22-27`).
   A client that simply omits the parameter takes the stored value with no
   permission check. Today only bots can have this field set
   (`patch_bot_backend`, `zerver/views/users.py:555-558`, which itself applies no
   check to it) and guests cannot own bots, so there is no attacker-reachable
   path — but the guard should move after the fallback. Same subsystem as the
   event-queue `narrow` finding reported previously.

2. **Private channels can be added to default channel *groups*.**
   `add_default_stream` (`zerver/views/streams.py:169-178`) explicitly rejects
   private channels — "Private channels cannot be made default." — because every
   new user would be subscribed. `create_default_stream_group` and
   `update_default_stream_group_streams`
   (`zerver/views/streams.py:181-241`) accept private channels, and
   `do_create_default_stream_group` / `do_add_streams_to_default_stream_group`
   (`zerver/actions/default_streams.py:84-131`) do not check `invite_only`
   either. The group's channels are then broadcast to every non-guest member
   (`notify_default_stream_groups` → `active_non_guest_user_ids`), shown on the
   signup page (`zerver/views/registration.py:971`), and auto-subscribed on
   selection (`zerver/actions/create_user.py:162-166`). This requires
   `can_manage_default_streams()`, which is `is_realm_admin`
   (`zerver/models/users.py:907-908`), and the actor must already have content
   access to pass `access_stream_by_name`, so it is an admin-only footgun rather
   than an escalation — but the missing check is inconsistent with the sibling
   endpoint.
