# Security finding: guests receive every public-channel message via the event-queue `narrow` parameter

**Component:** Tornado event system (`zerver/tornado/event_queue.py`)
**Class:** Broken access control / information disclosure
**Severity:** High (authenticated bypass; complete, ongoing disclosure of all
public-channel content to a user restricted from it)
**Affected commit:** `9b302b8b385c75b01f80f9573be0519c7ddbc4b4` (`main`)

## Summary

Any guest user can register an event queue with a non-empty `narrow` and, as a
side effect, be subscribed to the organization-wide *public channel firehose* in
Tornado. From that point on the guest receives a real-time `message` event —
full content, topic, sender identity and message ID — for **every message sent
to every public channel in the organization**, including the channels they are
not subscribed to and cannot otherwise read.

A guest is documented and enforced elsewhere as being able to read only the
channels they have been explicitly subscribed to. No `narrow` operand is
validated against channel access, and `[["is", "unread"]]` acts as a wildcard
that matches every channel message, so a single API call yields the whole
organization's public traffic.

Private channels and direct messages are **not** affected, and logged-out
spectators are not affected (no queue is allocated for them).

## Why this is not intended behavior

Four independent sources in the codebase say a guest must not get this data.

1. **The help center states the boundary explicitly.**
   `starlight_help/src/content/docs/guest-users.mdx:23-25` — Guest users
   *cannot* "See private or public channels, unless they have been specifically
   subscribed to the channel."

2. **The documented way to request this firehose is permission-checked; this
   path is the same firehose without the check.** `all_public_streams` is
   rejected for exactly the users this bug lets in:

   - `zerver/views/events_register.py:72`
   - `zerver/tornado/views.py:237`

   ```python
   if all_public_streams and not user_profile.can_access_public_streams():
       raise JsonableError(_("User not authorized for this query"))
   ```

   `UserProfile.can_access_public_streams()` (`zerver/models/users.py:952-953`)
   is `return not self.is_guest`, so guests are the only users this gate
   excludes — it exists solely to keep guests out of the firehose.

3. **The API reference documents `narrow` as a pure filter that can never widen
   access.** `zerver/openapi/zulip.yaml:30807-30824`:

   > Unlike the API for [fetching messages](/api/get-messages), this narrow
   > parameter is simply a filter on messages that the user receives through
   > their channel subscriptions (or because they are a recipient of a direct
   > message).
   >
   > This means that a client that requests a `narrow` filter of
   > `[["channel", "Denmark"]]` will receive events for new messages sent to
   > that channel while the user is subscribed to that channel. **The client
   > will not receive any message events at all if the user is not subscribed
   > to `"Denmark"`.**
   >
   > See the `all_public_streams` parameter for how to process all public
   > channel messages in an organization.

   The implementation contradicts this for every user, but only crosses a
   security boundary for guests.

4. **The equivalent history endpoint is correctly restricted.** For a guest,
   `get_base_query_for_search` (`zerver/lib/narrow.py:997-1004`) omits the
   `Q(invite_only=False)` clause, and `ok_to_include_history`
   (`zerver/lib/narrow.py:789-793`) returns `False`, so `GET /messages` on an
   unsubscribed public channel correctly returns nothing. Only the live event
   path leaks — a clear inconsistency rather than a design decision.

## Root cause

`add_to_client_dicts` treats "has a narrow" as equivalent to "wants all public
streams", but only the latter was ever permission-checked.

`zerver/tornado/event_queue.py:551-554`

```python
def add_to_client_dicts(client: ClientDescriptor) -> None:
    user_clients.setdefault(client.user_profile_id, []).append(client)
    if client.all_public_streams or client.narrow != []:
        realm_clients_all_streams.setdefault(client.realm_id, []).append(client)
```

## Full code path

1. **Queue creation — narrow is never access-checked.**
   `events_register_backend` (`zerver/views/events_register.py:72`) gates
   `all_public_streams`, then passes `narrow` straight through.
   `check_narrow_for_events` (`zerver/lib/narrow_predicate.py:16-26`) validates
   only that the *operator* is one of `channel`/`stream`/`topic`/`sender`/`is`;
   it never resolves the operand to a `Stream` or checks subscription.

2. **The client joins the realm-wide firehose.**
   `allocate_client_descriptor` → `add_to_client_dicts`
   (`zerver/tornado/event_queue.py:551-554`) adds the descriptor to
   `realm_clients_all_streams[realm_id]` because `narrow != []`.

3. **Every public-channel message is fanned out to that bucket.**
   `zerver/actions/message_send.py:1245-1259` attaches `stream_name`/`realm_id`
   to the event only for public channels — the comment there calls this "where
   authorization for single-stream get_updates happens", i.e. the code assumes
   any client in this bucket is allowed to see public channels.

   `get_client_info_for_message_event` (`zerver/tornado/event_queue.py:1110-1117`)
   then adds **every** descriptor in the bucket to the recipient set, with
   `flags=[]`, independently of the actual message recipients:

   ```python
   if "stream_name" in event_template and not event_template.get("invite_only"):
       realm_id = event_template["realm_id"]
       for client in get_client_descriptors_for_realm_all_streams(realm_id):
           send_to_clients[client.event_queue.id] = dict(
               client=client, flags=[], is_sender=is_sender_client(client),
           )
   ```

4. **Delivery is gated only by the narrow filter, which does no access
   control.** `process_message_event` (`zerver/tornado/event_queue.py:1307-1348`)
   builds the full payload via `get_client_payload(...)` and calls
   `client.accepts_event(user_event)`
   (`zerver/tornado/event_queue.py:245-257`), which for `type == "message"`
   delegates to `build_narrow_predicate` (`zerver/lib/narrow_predicate.py:33-84`).
   That predicate compares channel name, topic, sender e-mail and flags. It has
   no notion of subscriptions or permissions.

### The `[["is", "unread"]]` wildcard

Because step 3 passes `flags=[]`, the `is:unread` operand — `if "read" in
flags: return False` — always passes, making it a match-everything narrow.
Executing the real `zerver/lib/narrow_predicate.py` against a synthetic channel
message with `flags=[]` (script kept at
`/tmp/.../scratchpad/verify_predicate.py`) gives:

```
[['is', 'unread']]                     -> delivered=True
[['channel', 'core team']]             -> delivered=True
[['sender', 'ceo@example.com']]        -> delivered=True
[['topic', 'layoffs']]                 -> delivered=True
[['is', 'starred']]                    -> delivered=False
[['is', 'mentioned']]                  -> delivered=False
```

So `[["is","unread"]]` exfiltrates everything, and `[["channel","<name>"]]`
targets one channel.

## Steps to reproduce

Setup: an organization with a public channel `core team`; a guest user
`guest@example.com` who is **not** subscribed to it; any non-guest user who is.

1. **Confirm the guest genuinely lacks access** (control case — this is
   correctly denied today):

   ```bash
   curl -sSG https://ZULIP.EXAMPLE.COM/api/v1/messages \
     -u guest@example.com:GUEST_API_KEY \
     --data-urlencode 'anchor=newest' \
     --data-urlencode 'num_before=10' \
     --data-urlencode 'num_after=0' \
     --data-urlencode 'narrow=[["channel","core team"]]'
   ```

   Returns no messages from `core team`.

2. **As the guest, register an event queue with a wildcard narrow:**

   ```bash
   curl -sSX POST https://ZULIP.EXAMPLE.COM/api/v1/register \
     -u guest@example.com:GUEST_API_KEY \
     --data-urlencode 'event_types=["message"]' \
     --data-urlencode 'narrow=[["is","unread"]]'
   ```

   Note the returned `queue_id` and `last_event_id`.

3. **As the non-guest user, send a message to `core team`** (a channel the
   guest is not subscribed to).

4. **As the guest, poll the queue:**

   ```bash
   curl -sSG https://ZULIP.EXAMPLE.COM/api/v1/events \
     -u guest@example.com:GUEST_API_KEY \
     --data-urlencode 'queue_id=QUEUE_ID' \
     --data-urlencode 'last_event_id=LAST_EVENT_ID'
   ```

   **Expected (per docs):** no `message` events, since the guest is not
   subscribed to `core team`.
   **Actual:** a `message` event containing the full rendered `content`,
   `subject` (topic), `display_recipient` (`"core team"`), `sender_id`,
   `sender_full_name` and `sender_email`.

Repeating step 4 in a loop streams the organization's entire public-channel
traffic to the guest indefinitely. Substituting
`narrow=[["channel","<name>"]]` targets a specific channel and also confirms
the existence of channels the guest should not be able to enumerate.

### Regression test

Modelled on the existing `StreamWatchersTest`
(`zerver/tests/test_event_queue.py:94-136`), which uses the same harness to
show that an `all_public_streams` queue receives messages for an unsubscribed
channel. This test should pass and currently fails:

```python
class GuestNarrowEventQueueTest(ZulipTestCase):
    def test_guest_does_not_receive_unsubscribed_public_channel_messages(self) -> None:
        polonius = self.example_user("polonius")
        cordelia = self.example_user("cordelia")
        self.assertTrue(polonius.is_guest)
        self.subscribe(cordelia, "Denmark")
        self.unsubscribe(polonius, "Denmark")

        queue_data = dict(
            all_public_streams=False,
            apply_markdown=True,
            client_gravatar=True,
            client_type_name="website",
            event_types=["message"],
            last_connection_time=time.time(),
            queue_timeout=0,
            realm_id=polonius.realm_id,
            user_profile_id=polonius.id,
            narrow=[["is", "unread"]],
        )
        client = allocate_client_descriptor(queue_data)

        self.send_stream_message(cordelia, "Denmark", content="not for guests")

        # Currently fails: the guest's queue contains the message.
        self.assert_length(client.event_queue.contents(), 0)
```

(Not committed to `zerver/tests/`, since a knowingly failing test would break
CI.)

## Impact

- A guest — typically an external contractor or customer — reads all public
  channel messages in the organization in real time, defeating the entire
  purpose of the guest role.
- Disclosure covers message content, topic names, channel names and sender
  identities.
- Only the guest's own API key is required; no interaction from any other user.
- Historical messages remain protected, so the leak is forward-looking from the
  moment the queue is registered — but a queue can be held open indefinitely.

Rough CVSS v3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5), which understates
the practical severity for a chat product whose guest role is a primary
confidentiality control.

## Suggested fix

The guest's *own* subscriptions are delivered through the separate `users` loop
in `get_client_info_for_message_event`, not through
`realm_clients_all_streams`. So excluding guests from that bucket removes the
leak without affecting legitimate narrow filtering.

Capture the permission at queue-creation time in Django (where the
`UserProfile` is available), store it on the descriptor alongside
`all_public_streams`, and gate on it:

```python
def add_to_client_dicts(client: ClientDescriptor) -> None:
    user_clients.setdefault(client.user_profile_id, []).append(client)
    if client.can_access_public_streams and (client.all_public_streams or client.narrow != []):
        realm_clients_all_streams.setdefault(client.realm_id, []).append(client)
```

Implementation notes:

- Add the field to `new_queue_data` in `get_events_backend`
  (`zerver/tornado/views.py:252-274`) from
  `user_profile.can_access_public_streams()`.
- `ClientDescriptor.to_dict`/`from_dict` must round-trip it; queues restored
  from an older `event_queues.json` have no such key, so it should **fail
  closed** rather than defaulting to `True`.
- Worth adding a matching test that a non-guest with a narrow still receives
  messages from unsubscribed public channels, to pin the behavior members rely
  on.
- Separately, the `narrow` documentation at
  `zerver/openapi/zulip.yaml:30807-30824` does not match the implementation for
  non-guests either; that is a documentation/behavior mismatch worth resolving,
  though not a security issue.
