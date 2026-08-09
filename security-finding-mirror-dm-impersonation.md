# Any user can forge direct messages from another user via the mirroring client names

**Component:** `zerver/views/message_send.py:173-212` (`send_message_backend`),
`zerver/lib/recipient_users.py:14-53` (`get_recipient_from_user_profiles`)
**Class:** Message forgery / user impersonation (integrity)
**Severity:** Medium–High. CVSS v3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = 6.5
**Affected commit:** `9b302b8b385c75b01f80f9573be0519c7ddbc4b4`

## Important caveat on intent, stated up front

Unlike the earlier findings in this branch, **the mechanism here is
deliberate and documented in the code**. `send_message_backend` carries an
explicit block comment describing the mirroring security model. I am therefore
*not* claiming the feature is an accident.

What I am reporting is narrower: the stated rationale for allowing this without
a permission check does not cover the capability the code actually grants.
That gap is what follows. A maintainer may reasonably read this as accepted
legacy risk; I am flagging it rather than asserting it is a clear-cut bug.

## Summary

The IRC/Jabber mirroring integrations let a request nominate an arbitrary
`sender` for a direct message. Stream mirroring requires the privileged
`can_forge_sender` flag; **direct-message mirroring requires no permission at
all** — only that the request declares one of three client names, which is a
free-form, caller-supplied string.

Any authenticated user (including a guest) in an organization that has at least
one configured email domain can therefore post a direct message that Zulip
attributes to another user, with attacker-chosen content, delivered to
themselves *and to any other users they name*.

## The gap in the stated rationale

`zerver/views/message_send.py:173-186`:

```python
    if client.name in ["irc_mirror", "jabber_mirror", "JabberMirror"]:
        # Here's how security works for mirroring:
        #
        # For direct messages, the message must be (1) both sent and
        # received exclusively by users in your realm, and (2)
        # received by the forwarding user.
        ...
        if recipient_type_name != "private" and not can_forge_sender:
            raise JsonableError(_("User not authorized for this query"))
```

and `zerver/lib/recipient_users.py:23-35`:

```python
    if forwarded_mirror_message:
        # ... users can only submit to Zulip private
        # messages they personally received, and here we do the check
        # for whether forwarder_user_profile is among the private
        # message recipients of the message.
        assert forwarder_user_profile is not None
        if forwarder_user_profile.id not in recipient_profiles_map:
            raise ValidationError(_("User not authorized for this query"))
```

The justification for skipping a permission check is *"users can only submit to
Zulip private messages they personally received"* — i.e. you are already party
to the conversation, so forging it tells you nothing you didn't have.

The check implements **"the forwarder is *a* recipient"**, not **"the forwarder
is the *only* recipient"**. The recipient set is unbounded beyond that. So the
attacker can include uninvolved third parties, who then see a message
attributed to someone who never wrote it. Nothing in the quoted rationale
covers that case, and it is the case with real impact.

Note also the asymmetry two lines apart in the same function: Zulip already has
a permission concept for exactly this capability (`can_forge_sender`) and
applies it to the channel case, but not the direct-message case.

## Why it is reachable by any user

The client name is not a property of the connection or the account — it is
read straight from the request. `zerver/middleware.py:255-260` (`parse_client`):

```python
    # If the API request specified a client in the request content,
    # that has priority. Otherwise, extract the client from the
    # USER_AGENT.
    if req_client is not None:
        return req_client, None
```

So `client=irc_mirror` on any request is sufficient to enter the mirroring
branch. There is no bot-type check, no `can_forge_sender` check, and no
realm-level gate — `is_zephyr_mirror_realm` no longer exists anywhere in the
codebase.

The only real constraint is `same_realm_irc_user` / `same_realm_jabber_user`
(`zerver/views/message_send.py:71-101`), which requires the *domain* of each
referenced address to match a `RealmDomain` row:

```python
    domain = Address(addr_spec=email).domain.lower()
    domain = domain.removeprefix("irc.")
    return RealmDomain.objects.filter(realm=user_profile.realm, domain=domain).exists()
```

This is a check on the email **domain**, not on who the sender is. Any
organization that restricts signup to its own domain — the common enterprise
configuration — satisfies it for every employee address.

## Chain

1. Attacker POSTs to `/api/v1/messages` with `client=irc_mirror`,
   `type=private`, `sender=<victim>`, `to=[<attacker>, <bystander>]`.
2. `parse_client` returns `irc_mirror` from the request parameter.
3. `send_message_backend` enters the mirroring branch; the
   `can_forge_sender` gate is skipped because `recipient_type_name == "private"`.
4. `create_mirrored_message_users` domain-checks sender and recipients, then
   calls `create_mirror_user_if_needed` for each — which returns the existing
   `UserProfile` for a real user (`zerver/actions/message_send.py:152-169`), or
   **creates a new `is_mirror_dummy` account** for an address that has never
   signed up.
5. `sender_user_profile = get_user_including_cross_realm(sender_email, realm)`
   resolves to the victim's real `UserProfile` (this requires the victim's
   `UserProfile.email` to be their real address, i.e. the common
   `email_address_visibility = EVERYONE` configuration).
6. `check_message` runs with `sender = victim`.
   `recipient_for_user_profiles(..., forwarded_mirror_message=True,
   forwarder_user_profile=attacker, sender=victim)` passes, because the
   attacker is among the recipients.
7. `do_send_messages` stores a `Message` with `sender = victim`. Every
   recipient — including the bystander — receives a direct message attributed
   to the victim.

## Steps to reproduce

Setup: an organization with an email domain configured (Organization settings →
**Organization permissions** → restrict signup to `example.com`, which creates
the `RealmDomain` row). `mallory@example.com` is any ordinary member or guest;
`alice@example.com` and `bob@example.com` are other members.

1. **As Mallory**, send the forged message:

   ```bash
   curl -sSX POST https://ZULIP.EXAMPLE.COM/api/v1/messages \
     -u mallory@example.com:MALLORY_API_KEY \
     --data-urlencode 'client=irc_mirror' \
     --data-urlencode 'type=private' \
     --data-urlencode 'sender=alice@example.com' \
     --data-urlencode 'to=["mallory@example.com","bob@example.com"]' \
     --data-urlencode 'content=Please approve the wire transfer to the new vendor account.'
   ```

   **Expected:** rejected — Mallory has no permission to send as Alice.
   **Actual:** `{"result":"success","id":<message_id>}`.

2. **As Bob**, open the direct message. It appears in a group DM from **Alice**,
   with `sender_id` and `sender_full_name` set to Alice. Alice never sent it,
   and it appears in her own DM history as though she did.

3. **Contrast — the channel path is correctly gated.** The same request with
   `type=stream` is rejected with `"User not authorized for this query"` unless
   the caller has `can_forge_sender`.

4. **Side effect — account creation.** Substituting an address that has never
   signed up (`sender=ceo@example.com`) causes
   `create_mirror_user_if_needed` to create an `is_mirror_dummy` `UserProfile`
   for it. That account is later claimable through the normal signup flow
   (`validate_email_not_already_in_realm(..., allow_inactive_mirror_dummies=True)`),
   so the real person inherits an account whose message history already contains
   attacker-authored messages attributed to them.

## Impact

- Convincing impersonation of any colleague inside the trusted chat channel —
  the classic business-email-compromise setup, but without the tells that make
  a spoofed email suspicious.
- Available to **any** authenticated account, including guests, with no
  elevated permission.
- The forged message is stored as a genuine `Message` row with the victim as
  sender; it appears in the victim's own history. The only distinguishing
  signal is `sending_client`, which is not surfaced prominently in the UI.
- Bounded to organizations with a configured `RealmDomain` and to victims whose
  `UserProfile.email` is their real address. No confidentiality impact: the
  attacker learns nothing they could not already see.

## Suggested fix

Either require a permission for the direct-message mirroring path as is already
done for channels, or tighten the constraint so it actually matches the stated
rationale — that the forwarder is the *sole* recipient:

```python
    if forwarded_mirror_message:
        assert forwarder_user_profile is not None
        if set(recipient_profiles_map) - {sender.id} != {forwarder_user_profile.id}:
            raise ValidationError(_("User not authorized for this query"))
```

The stricter form preserves the legitimate mirroring use case (a bot replaying
a 1:1 conversation it received) while removing the ability to show a forged
message to anyone else. If the multi-recipient case must keep working for real
mirroring deployments, gating the whole branch on a dedicated permission — or
on the acting user being a bot the realm has designated for mirroring — would
be the more robust fix.
