# Historical provider-state recovery

Fulmar admits a private `HarnessHome` only with the exact v3 receipt and provider-history
privacy epoch 1. A v1/v2 receipt or a receiptless home is historical. Startup stops agent
work and asks for an explicit choice. Detection and **Keep Stopped** do not access
Keychain, enumerate the home's children, or mutate the existing home. A genuinely absent
home is created empty at v3/epoch 1; Fulmar does not probe or import `~/.dsh` and does not
access a recovery credential during that clean installation.

Startup also detects an interrupted authenticated transaction without reading a
Keychain item or changing the recovery directory. A foreground launch presents a
typed **Resume Interrupted Recovery** decision bound to the exact parent, recovery
directory, and journal identities. A background wake remains stopped and may post a
notification, but it never initiates Keychain authorization or transaction recovery.

**Preserve, Keep Settings, and Start** and **Preserve and Start Clean** perform the same
bounded preservation transaction, with the copy choice authenticated in its journal:

1. For a new transaction, Fulmar obtains its app-owned, device-only authentication
   key only after that user action. An interrupted transaction can use only the
   existing key: it can never create a replacement. A legacy key that needs macOS
   authorization gets a separate foreground **Authorize and Retry** decision; no
   password prompt is initiated at launch.
2. A fixed owner-only, ACL-free transaction lock serializes all writers across app
   processes. A journal that predates creation of the fixed lock remains recoverable:
   the lock may be created only after an explicit Resume/Authorize action, followed by
   another exact identity check. An exact authenticated format-1 journal has no recorded
   import consent, so its deterministic upgrade is **Start Clean**. Before replacing it
   with the exact format-2 schema, Fulmar moves both the original whole home and any old
   staged or already-published output into separate identity-bound opaque quarantines.
   Neither tree is enumerated or deleted. A malformed, unauthenticated, or future journal
   fails closed. The initial authenticated journal is published exclusively and can never
   replace a concurrently created entry. The
   exact existing home is moved once to a unique directory under
   `HarnessHomeRecovery/receiptless-<UUID>` and is never overwritten or automatically
   deleted.
3. The historical home is an opaque preservation unit. Fulmar never lists, parses, or
   copies its sessions, storages, attachments, profiles, Skills, or unknown children.
   **Keep Settings** performs only two exact descriptor-relative probes and may copy an
   owner-controlled, bounded, `O_NOFOLLOW` regular `settings.yaml` or `settings.json`.
   **Start Clean** opens no child at all. Every other byte remains only in the preserved
   whole-home directory.
4. The repaired home receives a durable v3/epoch-1 receipt and is published atomically. The
   authenticated published journal remains durable until Fulmar presents that exact
   receipt and explicitly acknowledges it. A quit, crash, or relaunch before
   acknowledgement re-presents the same preserved-copy path and copied-entry list.
   Every journal, rename, copy, receipt, publish, and acknowledgement boundary is
   restart-reconcilable.
5. Fulmar shows the exact preserved-copy location and manual restore guidance. Only
   after that presentation is still current and the matching journal acknowledgement
   succeeds may it start a fresh runtime. Opening the preserved folder is optional.

If the key is unavailable, the journal is changed, a path or inode changes, an
extended ACL or unsafe root/settings link or permission is found, another process holds
the transaction lock, or a configured settings byte/deadline bound is reached, recovery fails closed.
Fulmar keeps the runtime stopped and offers the private recovery folder for manual
inspection; it never removes the original or quarantine as part of failure handling.

The fixed clean-install staging leaf is treated the same way: only an exact clean
v3/epoch-1 receipt proves that staging was created by this version and may be completed
or discarded. Receiptless, malformed, v1/v2, unexpected-current, and future-schema
staging is preserved without child enumeration; startup either routes valid v1/v2 state
into the opaque foreground recovery flow or stops for manual review.
