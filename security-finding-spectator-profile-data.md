# Unauthenticated disclosure of every user's custom profile fields to spectators

**Component:** `zerver/views/users.py` — `GET /json/users` (`get_members_backend`)
**Class:** Broken access control — unauthenticated information disclosure
**Severity:** High (CVSS v3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5); the
most severe finding of this session, because it requires **no account at all**
**Affected commit:** `9b302b8b385c75b01f80f9573be0519c7ddbc4b4` (`main`,
unmodified mirror of `zulip/zulip`)

## Summary

In any Zulip organization with web-public channels enabled, an anonymous visitor
— no account, no invitation, no login — can issue a single unauthenticated GET
request and receive the **custom profile field values of every user in the
organization**: phone numbers, job titles, locations, birthdays, employee IDs,
social handles, pronouns, and any other custom field the organization has
configured.

The `include_custom_profile_fields` request parameter is passed straight through
to the serializer for spectators. The `/register` code path deliberately forces
this off for spectators, with a comment saying so; the `GET /json/users`
endpoint does not.

## Why this is not intended behavior

1. **The parallel code path forces it off for spectators, and says why.**
   `zerver/lib/events.py:709-717`:

   ```python
   state["raw_users"] = get_users_for_api(
       realm,
       user_profile,
       client_gravatar=client_gravatar,
       user_avatar_url_field_optional=user_avatar_url_field_optional,
       # Don't send custom profile field values to spectators.
       include_custom_profile_fields=user_profile is not None,
       user_list_incomplete=user_list_incomplete,
   )
   ```

2. **Spectators are denied the field definitions in the same file.**
   `zerver/lib/events.py:280-283`:

   ```python
   if user_profile is None:
       # Spectators can't access full user profiles or
       # personal settings, so we send an empty list.
       state["custom_profile_fields"] = []
   ```

3. **The serializer already scrubs a *less* sensitive field for spectators.**
   `zerver/lib/users.py:653-656` removes `timezone` for anonymous callers:

   ```python
   if acting_user is None:
       # Remove data about other users which are not useful to spectators
       # or can reveal personal information about a user.
       del result["timezone"]
   ```

   Twenty lines later, at `zerver/lib/users.py:694-696`, the entire custom
   profile payload is attached with no equivalent guard:

   ```python
   elif custom_profile_field_data is not None:
       result["profile_data"] = custom_profile_field_data
   ```

   Stripping `timezone` as "personal information" while emitting phone numbers
   and home addresses is not a coherent policy — it is a missed case.

4. **The existing spectator test never exercises the parameter.**
   `zerver/tests/test_users.py:3876` (`test_get_users_for_spectators`) checks
   that spectators can list users, and asserts query counts and membership
   counts, but never passes `include_custom_profile_fields`. That is why the gap
   survived.

## The defect

`zerver/views/users.py:863-887` — the anonymous branch sets `user_profile = None`
but forwards the client's `include_custom_profile_fields` unchanged:

```python
@typed_endpoint
def get_members_backend(
    request: HttpRequest,
    maybe_user_profile: UserProfile | AnonymousUser,
    *,
    client_gravatar: Json[bool] = True,
    include_custom_profile_fields: Json[bool] = False,   # <-- client-controlled
    user_ids: Json[list[int]] | None = None,
) -> HttpResponse:
    if isinstance(maybe_user_profile, UserProfile):
        user_profile = maybe_user_profile
        realm = user_profile.realm
    else:
        realm = get_valid_realm_from_request(request)
        if not realm.allow_web_public_streams_access():
            raise MissingAuthenticationError
        user_profile = None            # spectator

    data = get_user_data(
        user_profile,
        include_custom_profile_fields,  # <-- no spectator guard
        client_gravatar,
        user_ids=user_ids,
        realm=realm,
    )
```

## Full chain

1. **The endpoint is registered for anonymous access.** `zproject/urls.py:355-357`:

   ```python
   rest_path(
       "users", GET=(get_members_backend, {"allow_anonymous_user_web"}), POST=create_user_backend
   ),
   ```

   `zerver/lib/rest.py:199-205` permits unauthenticated calls carrying that flag
   for paths under `/json` (so the reachable URL is `/json/users`, not
   `/api/v1/users`). `csrf_protect` wraps it, which does not apply to GET.

2. **Spectators are treated as able to see every user.**
   `get_user_dicts_in_realm` (`zerver/lib/users.py:1051-1061`) calls
   `check_user_can_access_all_users(None)`, which returns `True` for spectators
   (`zerver/lib/users.py:727-731`), so **all** realm user dicts are returned —
   including users with restricted `can_access_all_users_group` visibility.

3. **Every custom profile value in the realm is fetched.**
   `get_users_for_api` (`zerver/lib/users.py:1126-1133`):

   ```python
   if include_custom_profile_fields:
       base_query = CustomProfileFieldValue.objects.select_related("field")
       if target_user is not None:
           custom_profile_field_values = base_query.filter(user_profile=target_user)
       else:
           custom_profile_field_values = base_query.filter(field__realm_id=realm.id)
       profiles_by_user_id = get_custom_profile_field_values(custom_profile_field_values)
   ```

4. **It is attached to each user row** at `zerver/lib/users.py:694-696`, with the
   `acting_user is None` check absent.

`GET /json/users/{id}` and `GET /json/users/{email}` are **not** affected — they
require authentication. The vector is specifically the list endpoint.

## Steps to reproduce

Setup: any Zulip organization with web-public channels enabled — i.e.
`settings.WEB_PUBLIC_STREAMS_ENABLED`, the realm's **Public access option**
turned on, and at least one web-public channel. This is a documented, promoted
Zulip feature used by many open-source communities. At least one user has a
custom profile field value set (Organization settings → Custom profile fields).

1. **Confirm the baseline** — as an anonymous client, the normal spectator
   listing returns no profile data:

   ```bash
   curl -sS 'https://ZULIP.EXAMPLE.COM/json/users' | jq '.members[0]'
   ```

   No `profile_data` key.

2. **Add the parameter** — still with no credentials, no cookie, no session:

   ```bash
   curl -sS 'https://ZULIP.EXAMPLE.COM/json/users?include_custom_profile_fields=true' \
     | jq '.members[] | {user_id, full_name, profile_data}'
   ```

   **Expected:** `profile_data` absent, matching `/register`, which forces
   `include_custom_profile_fields=False` for spectators.
   **Actual:** every user object carries a populated `profile_data` map of
   `{field_id: {value, rendered_value}}` — the whole organization's custom
   profile fields, dumped to an unauthenticated caller.

3. **Optional — target specific people:**

   ```bash
   curl -sS 'https://ZULIP.EXAMPLE.COM/json/users?include_custom_profile_fields=true&user_ids=\[11,12\]'
   ```

For contrast, `curl -sS 'https://ZULIP.EXAMPLE.COM/json/users'` against a realm
with no web-public channels correctly returns
`"Not logged in: API authentication or user session required"` (401) — the same
assertion the existing test at `zerver/tests/test_users.py:3881-3888` makes.

## Impact

- **No authentication of any kind.** Not a guest, not a low-privileged member —
  an anonymous Internet client.
- Discloses the full custom-profile dataset for every account in the
  organization. Zulip's own [custom profile fields](/help/custom-profile-fields)
  feature is marketed for exactly the data that hurts here: phone numbers,
  offices/locations, birthdays, job titles, manager, employee ID, GitHub/LinkedIn
  handles, pronouns.
- Also covers users whom the organization has restricted via
  `can_access_all_users_group`, since spectators short-circuit that check.
- Trivially scriptable and scalable — one request returns the entire directory.
- Non-obvious to operators: enabling one web-public channel silently exposes the
  whole staff directory, which is not what
  `/help/public-access-option` leads an administrator to expect.

I am recording this as High rather than Critical: it needs the organization to
have web-public access enabled, and it exposes profile metadata rather than
message content or credentials. Within organizations that use both features it
is, in practice, a full staff-directory breach to anonymous callers.

## Suggested fix

Mirror the `/register` path — never honor the flag for unauthenticated callers:

```python
    data = get_user_data(
        user_profile,
        # Don't send custom profile field values to spectators.
        include_custom_profile_fields and user_profile is not None,
        client_gravatar,
        user_ids=user_ids,
        realm=realm,
    )
```

Belt-and-braces, make the serializer enforce it too, next to the existing
spectator scrub in `format_user_row` (`zerver/lib/users.py:653-656`):

```python
    if acting_user is None:
        del result["timezone"]
        custom_profile_field_data = None
```

Add a regression test extending `test_get_users_for_spectators`
(`zerver/tests/test_users.py:3876`) that sets a custom profile field value,
requests `/json/users?include_custom_profile_fields=true` anonymously, and
asserts `profile_data` is absent from every returned member — and a companion
assertion that an authenticated member still receives it.
