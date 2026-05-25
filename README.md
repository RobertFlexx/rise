<p align="center">
  <img src="assets/rise-banner.svg" alt="rise - a small Ada-first privilege launcher" width="760">
</p>

<p align="center">
  <a href="https://www.adaic.org/"><img src="assets/badge-ada.svg" alt="Ada"></a>
  <a href="https://www.open-std.org/jtc1/sc22/wg14/"><img src="assets/badge-c.svg" alt="C"></a>
  <a href="https://www.linux-pam.org/"><img src="assets/badge-pam.svg" alt="Linux-PAM"></a>
  <a href="https://gcc.gnu.org/onlinedocs/gnat_ugn/"><img src="assets/badge-gnat.svg" alt="GNAT"></a>
  <a href="https://www.gnu.org/software/make/"><img src="assets/badge-make.svg" alt="Make"></a>
  <a href="https://www.kernel.org/"><img src="assets/badge-linux.svg" alt="Linux"></a>
</p>

# rise

`rise` is a small privilege launcher for Unix-like systems. Something i made on my freetime. It is meant to fill the space between the large, policy-rich world of `sudo` and the intentionally tiny shape of `doas`: structured configuration, PAM authentication, timestamped authentication persistence, clean environment handling, and a compact codebase that can be read without needing a week and a map.

The project is Ada-first. Ada owns the command-line handling, policy parser, rule evaluation, and execution decisions. C is kept as a narrow platform layer for the parts that are already C-shaped on Unix: PAM, user/group lookup, timestamp files, syslog, environment reset, and UID/GID switching. Ada is a nice language, and I'm probably gonna code in it more.

`rise` is not a fork of `sudo` or `doas`, and it does not copy either configuration language.

## Status

`rise` is experimental security software. It is designed with a serious threat model, but it has not had the years of review that `sudo` and OpenBSD `doas` have had. I'm open for people to do large tests on it for me (please)

Use it on test machines first. Read the code. Keep the policy small. Do not treat “smaller” as a substitute for review.

## What it does

`rise` lets an authorized user run a command as another account, usually `root`.

A normal run looks like this (replace pacman with whatever package manager you use):

```sh
rise id
rise pacman -Syu
rise -u nobody id
```

The flow is deliberately simple:

```text
resolve command
read /etc/rise.conf safely
match the first applicable rule
authenticate through PAM if required
reuse or write a timestamp ticket if enabled
sanitize the environment
switch to the target user
execv() the resolved command
```

There is no shell in the execution path.

## What rise does differently

### Compared with sudo

`sudo` is mature, portable, feature-heavy, and heavily deployed. It also carries decades of compatibility and a large policy surface.

`rise` is intentionally smaller:

- no sudoers syntax
- no plugin framework
- no LDAP policy layer
- no shell execution
- no command aliases or wildcard matching
- no arbitrary environment preservation
- exact-path command allowlists
- compact INI-style policy file
- Ada policy engine instead of a C policy parser

That makes `rise` easier to read and reason about, but not automatically more secure. `sudo` has the advantage of age, review, and battle testing.

### Compared with doas

`doas` is small, sharp, and famously boring in the best way.

`rise` keeps a similar preference for small policy, but adds a few things that some Linux users expect from a daily-driver privilege tool:

- PAM authentication by default
- timestamped authentication persistence
- per-rule persistence control
- per-rule timeout override
- `rise -k` to forget the current ticket
- `rise -C` to check configuration syntax
- structured INI-style rules
- configurable `secure_path`
- explicit `env_keep`
- syslog audit records
- local manpage

The tradeoff is that `rise` is larger than `doas`.

## Language split

| Part | Language | Purpose |
|---|---|---|
| `src/rise.adb` | [Ada](https://www.adaic.org/) | CLI, config parser, policy decisions, rule matching, command resolution, authentication policy, exec handoff |
| `src/rise_platform.c` | [C](https://www.open-std.org/jtc1/sc22/wg14/) | PAM, passwd/group database, secure file opens, ticket cache, syslog, environment reset, `setuid`, `setgid`, `initgroups` |
| `pam.d/rise` | [Linux-PAM](https://www.linux-pam.org/) | Authentication service configuration |
| `Makefile` | [make](https://www.gnu.org/software/make/) | Build and install targets |

Ada is important here because the highest-level trust decision is policy logic. The parser and rule evaluator are easier to audit when they are written in a language with bounds checks, strong typing, and explicit conversions. C is kept where it belongs: the thin Unix boundary.

## Features

- setuid-root native binary
- Ada policy engine
- Linux-PAM authentication
- deny-by-default policy
- first matching rule wins
- exact absolute-path command matching
- optional `cmd = any`
- timestamped authentication tickets
- per-terminal or per-session ticket scoping
- per-rule persistence control
- per-rule timeout override
- clean target environment
- configurable `secure_path`
- explicit validated `env_keep`
- config opened with `O_NOFOLLOW`
- config must be root-owned and not group/other-writable
- authpriv syslog logging
- local manpage
- password-failure humor that can be disabled

## Install

### Dependencies

You need:

- GNAT / `gnatmake`
- a C compiler
- Linux-PAM headers and libraries
- `make`

Package names vary by distribution. Look for packages similar to:

```text
gcc-ada
gnat
linux-pam
pam-devel
```

### Build

Build as your normal user:

```sh
make
```

### Install

Install as root:

```sh
sudo make install
```

The install target intentionally does not rebuild the program. This avoids the common problem where `sudo make install` loses the user’s `PATH` and cannot find `gnatmake`.

Installed paths:

```text
/usr/local/bin/rise
/etc/rise.conf
/etc/pam.d/rise
/usr/local/share/man/man1/rise.1
```

Expected binary permissions:

```sh
ls -l /usr/local/bin/rise
```

Expected shape:

```text
-rwsr-xr-x root root ... /usr/local/bin/rise
```

### If your files extracted with future timestamps

Some archives can confuse `make` if file modification times are in the future:

```sh
touch Makefile src/rise.adb src/rise_platform.c
make clean
make
sudo make install
```

## PAM setup

The default `pam.d/rise` uses `system-auth`, which works on many source-based or Arch-like systems:

```text
auth       include      system-auth
account    include      system-auth
```

On Debian or Ubuntu-like systems, use:

```text
auth       include      common-auth
account    include      common-account
```

If authentication always fails, compare `/etc/pam.d/rise` with a known working local service such as `su`, `login`, or `sudo`.

## Configuration

Policy lives in:

```text
/etc/rise.conf
```

Required permissions:

```sh
sudo chown root:root /etc/rise.conf
sudo chmod 0600 /etc/rise.conf
```

Rules are evaluated from top to bottom. The first matching rule wins. If nothing matches, access is denied.

### Example

```ini
[defaults]
format = 2
timestamp = yes
timestamp_timeout = 300
tty_tickets = yes
require_tty = no
jokes = on
secure_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
env_keep = TERM,COLORTERM,LANG,LC_*

[rule block-guest]
action = deny
who = user:guest
target = any
cmd = any

[rule wheel-root]
action = allow
who = group:wheel
target = root
auth = pam
persist = default
cmd = any

[rule safe-nopass]
action = allow
who = user:robert
target = root
auth = none
cmd = /usr/bin/id, /usr/bin/true
```

### Defaults

| Key | Meaning |
|---|---|
| `format` | Config format version. Current value: `2`. |
| `timestamp` | Enable or disable cached authentication tickets. |
| `timestamp_timeout` | Ticket lifetime in seconds. Default example: `300`. |
| `tty_tickets` | Scope tickets per terminal/session instead of globally per user. |
| `require_tty` | Refuse authentication without a TTY. |
| `jokes` | Enable or disable password-failure humor. |
| `secure_path` | Path used for resolving command names and setting final `PATH`. |
| `env_keep` | Comma-separated environment names or prefix patterns to preserve after validation. |

### Rule keys

| Key | Values | Meaning |
|---|---|---|
| `action` | `allow`, `deny` | Rule result. |
| `who` | `user:name`, `group:name` | Caller principal list. |
| `target` | `root`, `any`, `user` | Account the command may run as. |
| `auth` | `pam`, `none` | Authentication mode. |
| `persist` | `default`, `yes`, `no` | Whether PAM success should create a ticket. |
| `timeout` | seconds | Optional per-rule ticket timeout. |
| `cmd` | `any`, absolute paths | Command allowlist. |

Use `auth = none` only with narrow command allowlists. `auth = none` plus `cmd = any` is effectively giving that principal unrestricted access to the target account.

## Timestamp persistence

After successful PAM authentication, `rise` writes a root-owned ticket under:

```text
/run/rise/tickets
```

Tickets are scoped by:

```text
caller uid + target uid + tty/session
```

by default.

To forget the current ticket:

```sh
rise -k
```

To force non-interactive behavior:

```sh
rise -n id
```

If no valid ticket exists and PAM would be required, `-n` fails instead of prompting.

## Common commands

Check config syntax:

```sh
rise -C
```

Run a command as root:

```sh
rise id
```

Run as another user:

```sh
rise -u nobody id
```

Forget the current cached authentication:

```sh
rise -k
```

Read the manual:

```sh
man rise
```

## Logging

`rise` logs allow/deny decisions through `LOG_AUTHPRIV` syslog.

Depending on your system, check one of:

```sh
journalctl -t rise
sudo tail -f /var/log/auth.log
sudo tail -f /var/log/secure
```

## Security notes

`rise` is designed to fail closed. It refuses:

- symlinked config files
- non-root-owned config files
- group/other-writable config files
- relative paths containing slashes
- arbitrary environment inheritance
- unknown config sections or keys
- unmatched requests

It intentionally avoids:

- shell command execution
- wildcard command matching
- config includes
- plugin loading
- remote policy backends
- sudoers compatibility
- doas.conf compatibility

This keeps the policy surface small.

## Stuff i needa do

Useful future work:

- command digest pinning
- fuzz tests for the config parser
- regression test suite for allow/deny cases
- configurable log format
- optional I/O logging
- `configure` script or `pkg-config` checks for PAM
- distro packaging

## License

MIT License
