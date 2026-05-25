# Security notes for rise

`rise` is intentionally small, but privilege boundaries are never casual.

## Things this does

- refuses non-root-owned `/etc/rise.conf`
- refuses group/other-writable `/etc/rise.conf`
- opens config using `O_NOFOLLOW`
- denies by default
- first match wins
- avoids shell execution entirely
- resolves command names using `secure_path`
- cleans environment before executing the target command
- stores auth tickets under root-owned `/run/rise/tickets`
- validates timestamp ticket owner, mode, type, contents, and age
- logs allow/deny decisions to authpriv syslog

## Things this intentionally doesnt do

- no sudoers compatibility
- no wildcard command matching
- no config includes
- no plugin system
- no arbitrary env preservation
- no command digests yet
- no I/O logging yet
- no SELinux/AppArmor policy integration yet

## Recommended first rule

Start with narrow command rules:

```ini
[rule test-safe]
action = allow
who = user:test
target = root
auth = pam
cmd = /usr/bin/id, /usr/bin/true
```

Only add `cmd = any` after testing.
