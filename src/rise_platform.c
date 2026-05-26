#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RISE_RUN_DIR "/run/rise"
#define RISE_TICKET_DIR "/run/rise/tickets"
#define RISE_TICKET_VERSION "rise-ticket-v3"
#define RISE_TICKET_SCOPE_MARKER "rise ticket scope: terminal-shell-v4"
const char rise_ticket_scope_marker[] = RISE_TICKET_SCOPE_MARKER;
#define RISE_DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

static const char *wrong_jokes[] = {
    "do you have memory loss, or is the keyboard doing improv?",
    "that password had all the confidence and none of the correctness.",
    "you numbnutted scoundrel! remember your password!",
    "the password goblin rejected your offering.",
    "bruh, the letters are not in the right ceremonial order.",
    "authentication said 'nah, I'm good.'",
    "that was not the password. It was password-adjacent fan fiction.",
    "your fingers just filed a bug report against your memory.",
    "wrong password. Somewhere, a sticky note is disappointed.",
    "the vault remains unimpressed.",
    "that secret was so secret even you didn't know it.",
    "root looked at that password and locked the door harder.",
    "you have angered the authentication ferret.",
    "the terminal has entered disappointment mode.",
    "wrong. Somewhere, /etc/shadow smirked.",
    "you fed PAM a crayon sandwich.",
    "PAM rejected it with the emotional energy of a DMV clerk.",
    "no dice, no root, no soup.",
    "wrong. Time to reboot the meat RAM.",
    "authorization failed. You have been bonked by policy.",
    "PAM said no in a very official little hat.",
    "wrong. You are one typo away from inventing a new language.",
    "wrong. Your keyboard is writing checks your memory can't cash."
};

static const char *final_jokes[] = {
    "three strikes. The password goblin has escorted you from the premises.",
    "failed 3 times. Congratulations, you have authenticated as a potato.",
    "no more tries. Go drink water and interrogate your memory.",
    "authentication failed 3 times. The root dragon is laughing in lowercase.",
    "three misses. Even the terminal felt that one.",
    "3 bad passwords. The Council of Remembering Things has denied your appeal.",
    "final denial. Please reboot the meat computer and try later.",
    "you have been defeated by your own secret. Ancient tragedy."
};

static size_t pick_index(size_t count, int attempt) {
    uintptr_t mix = (uintptr_t)&count;
    mix ^= (uintptr_t)getpid() << 7;
    mix ^= (uintptr_t)time(NULL) << 13;
    mix ^= (uintptr_t)attempt * 2654435761u;
    return count ? (size_t)(mix % count) : 0;
}

void rise_free(char *ptr) {
    free(ptr);
}

static int mode_has_any_exec(mode_t mode) {
    return (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

static int executable_stat_ok(const struct stat *st) {
    if (!st) return 0;
    if (!S_ISREG(st->st_mode)) return 0;
    if (!mode_has_any_exec(st->st_mode)) return 0;

    /* Refuse executables that can be modified by group or others. This is
       deliberately stricter than execve(2). A privileged launcher should not
       treat mutable executables as stable policy targets. */
    if ((st->st_mode & (S_IWGRP | S_IWOTH)) != 0) return 0;
    return 1;
}

int rise_canonical_executable(const char *path, char **out_path) {
    if (!path || !out_path) return -1;
    *out_path = NULL;

    if (path[0] != '/') return -2;

    char *resolved = realpath(path, NULL);
    if (!resolved) return -3;

    struct stat st;
    if (stat(resolved, &st) != 0 || !executable_stat_ok(&st)) {
        free(resolved);
        return -4;
    }

    *out_path = resolved;
    return 0;
}

int rise_file_is_executable(const char *path) {
    char *resolved = NULL;
    int r = rise_canonical_executable(path, &resolved);
    free(resolved);
    return r == 0 ? 0 : -1;
}

static int mkdir_secure(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;

    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return -1;
    if (st.st_uid != 0) return -1;
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) return -1;

    if (chmod(path, 0700) != 0) return -1;
    return 0;
}

static int ensure_ticket_dirs(void) {
    if (mkdir_secure(RISE_RUN_DIR) != 0) return -1;
    if (mkdir_secure(RISE_TICKET_DIR) != 0) return -1;
    return 0;
}

int rise_secure_read_config(const char *path, char **out_text, size_t *out_len, size_t max_len) {
    if (!path || !out_text || !out_len || max_len == 0) return -1;
    *out_text = NULL;
    *out_len = 0;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }

    if (!S_ISREG(st.st_mode)) { close(fd); return -2; }
    if (st.st_uid != 0) { close(fd); return -3; }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) { close(fd); return -4; }
    if (st.st_size < 0 || (size_t)st.st_size > max_len) { close(fd); return -5; }
    if (st.st_nlink != 1) { close(fd); return -6; }

    char *buf = calloc((size_t)st.st_size + 1, 1);
    if (!buf) { close(fd); return -1; }

    size_t used = 0;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, buf + used, (size_t)st.st_size - used);
        if (got < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (got == 0) break;
        used += (size_t)got;
    }

    close(fd);

    if (memchr(buf, '\0', used) != NULL) {
        free(buf);
        return -7;
    }

    buf[used] = '\0';
    *out_text = buf;
    *out_len = used;
    return 0;
}

char *rise_username_for_uid(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (!pw || !pw->pw_name) return NULL;
    return strdup(pw->pw_name);
}

int rise_lookup_user(const char *name, uid_t *out_uid, gid_t *out_gid,
                     char **out_home, char **out_shell, char **out_name) {
    if (!name || !out_uid || !out_gid || !out_home || !out_shell || !out_name) return -1;

    *out_home = NULL;
    *out_shell = NULL;
    *out_name = NULL;

    struct passwd *pw = getpwnam(name);
    if (!pw) return -1;

    char *home = strdup(pw->pw_dir ? pw->pw_dir : "/");
    char *shell = strdup(pw->pw_shell ? pw->pw_shell : "/bin/sh");
    char *real_name = strdup(pw->pw_name ? pw->pw_name : name);
    if (!home || !shell || !real_name) {
        free(home);
        free(shell);
        free(real_name);
        return -1;
    }

    *out_uid = pw->pw_uid;
    *out_gid = pw->pw_gid;
    *out_home = home;
    *out_shell = shell;
    *out_name = real_name;
    return 0;
}

int rise_user_in_group(const char *user, const char *group) {
    if (!user || !group) return 0;

    struct passwd *pw = getpwnam(user);
    struct group *gr = getgrnam(group);
    if (!pw || !gr) return 0;
    if (pw->pw_gid == gr->gr_gid) return 1;

    int ngroups = 0;
    getgrouplist(user, pw->pw_gid, NULL, &ngroups);
    if (ngroups <= 0 || ngroups > 4096) return 0;

    gid_t *groups = calloc((size_t)ngroups, sizeof(gid_t));
    if (!groups) return 0;

    int ret = getgrouplist(user, pw->pw_gid, groups, &ngroups);
    if (ret < 0) { free(groups); return 0; }

    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == gr->gr_gid) { free(groups); return 1; }
    }

    free(groups);
    return 0;
}

static int valid_env_name(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_')) return 0;
    }
    return 1;
}

static int valid_env_value(const char *s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n > 4096) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < 32 || *p == 127) return 0;
    }
    return 1;
}

static int dangerous_env_name(const char *name) {
    if (!name) return 1;
    if (strncmp(name, "LD_", 3) == 0) return 1;
    if (strncmp(name, "DYLD_", 5) == 0) return 1;
    if (strncmp(name, "PYTHON", 6) == 0) return 1;
    if (strncmp(name, "PERL", 4) == 0) return 1;
    if (strncmp(name, "RUBY", 4) == 0) return 1;
    if (strncmp(name, "GEM_", 4) == 0) return 1;
    if (strcmp(name, "GCONV_PATH") == 0) return 1;
    if (strcmp(name, "MALLOC_CHECK_") == 0) return 1;
    if (strcmp(name, "MALLOC_PERTURB_") == 0) return 1;
    if (strcmp(name, "IFS") == 0) return 1;
    if (strcmp(name, "ENV") == 0) return 1;
    if (strcmp(name, "BASH_ENV") == 0) return 1;
    if (strcmp(name, "SHELLOPTS") == 0) return 1;
    return 0;
}

static int keep_match(const char *name, const char *item, size_t n) {
    while (n > 0 && (*item == ' ' || *item == '\t')) { item++; n--; }
    while (n > 0 && (item[n - 1] == ' ' || item[n - 1] == '\t')) n--;
    if (n == 0) return 0;
    if (n >= 2 && item[n - 1] == '*') return strncmp(name, item, n - 1) == 0;
    return strlen(name) == n && strncmp(name, item, n) == 0;
}

static int should_keep_env(const char *name, const char *env_keep) {
    if (!name || !env_keep || !valid_env_name(name)) return 0;
    if (dangerous_env_name(name)) return 0;

    const char *p = env_keep;
    while (*p) {
        const char *start = p;
        while (*p && *p != ',') p++;
        if (keep_match(name, start, (size_t)(p - start))) return 1;
        if (*p == ',') p++;
    }

    return 0;
}

static int safe_dir_stat(const struct stat *st) {
    if (!st) return 0;
    if (!S_ISDIR(st->st_mode)) return 0;
    if (st->st_uid != 0) return 0;
    if ((st->st_mode & (S_IWGRP | S_IWOTH)) != 0) return 0;
    return 1;
}


static int path_entry_parent_is_safe(const char *dir) {
    char probe[PATH_MAX];

    if (!dir || dir[0] != '/') return 0;
    if (strlen(dir) >= sizeof(probe)) return 0;

    snprintf(probe, sizeof(probe), "%s", dir);

    for (;;) {
        struct stat st;
        if (stat(probe, &st) == 0) {
            return safe_dir_stat(&st);
        }

        if (errno != ENOENT && errno != ENOTDIR) return 0;

        char *slash = strrchr(probe, '/');
        if (!slash) return 0;

        if (slash == probe) {
            probe[1] = '\0';
        } else {
            *slash = '\0';
        }

        if (strcmp(probe, "/") == 0) {
            struct stat root_st;
            if (stat("/", &root_st) != 0) return 0;
            return safe_dir_stat(&root_st);
        }
    }
}

static int valid_secure_path(const char *path) {
    if (!path || !*path || strlen(path) > 4096) return 0;

    const char *p = path;
    while (*p) {
        const char *start = p;
        while (*p && *p != ':') {
            unsigned char c = (unsigned char)*p;
            if (c < 32 || c == 127) return 0;
            p++;
        }

        size_t len = (size_t)(p - start);
        if (len == 0 || len >= PATH_MAX) return 0;
        if (start[0] != '/') return 0;

        char dir[PATH_MAX];
        memcpy(dir, start, len);
        dir[len] = '\0';

        struct stat st;
        if (stat(dir, &st) == 0) {
            if (!safe_dir_stat(&st)) return 0;
        } else {
            if ((errno != ENOENT && errno != ENOTDIR) || !path_entry_parent_is_safe(dir)) {
                return 0;
            }
        }

        if (*p == ':') p++;
    }

    return 1;
}

struct kept_env { char *name; char *value; };

static void free_kept(struct kept_env *kept, size_t count) {
    if (!kept) return;
    for (size_t i = 0; i < count; i++) {
        free(kept[i].name);
        free(kept[i].value);
    }
}

extern char **environ;

int rise_apply_safe_env(const char *target_name, const char *target_home, const char *target_shell,
                        const char *secure_path, const char *env_keep) {
    struct kept_env kept[64];
    size_t kept_count = 0;
    memset(kept, 0, sizeof(kept));

    if (!secure_path || secure_path[0] == '\0') secure_path = RISE_DEFAULT_PATH;
    if (!valid_secure_path(secure_path)) return -1;

    for (char **ep = environ; ep && *ep && kept_count < 64; ep++) {
        char *eq = strchr(*ep, '=');
        if (!eq) continue;

        size_t name_len = (size_t)(eq - *ep);
        if (name_len == 0 || name_len > 128) continue;

        char name[129];
        memcpy(name, *ep, name_len);
        name[name_len] = '\0';

        const char *value = eq + 1;
        if (should_keep_env(name, env_keep) && valid_env_value(value)) {
            char *n = strdup(name);
            char *v = strdup(value);
            if (!n || !v) {
                free(n);
                free(v);
                free_kept(kept, kept_count);
                return -1;
            }
            kept[kept_count].name = n;
            kept[kept_count].value = v;
            kept_count++;
        }
    }

    if (clearenv() != 0) { free_kept(kept, kept_count); return -1; }

    if (setenv("PATH", secure_path, 1) != 0 ||
        setenv("USER", target_name ? target_name : "root", 1) != 0 ||
        setenv("LOGNAME", target_name ? target_name : "root", 1) != 0 ||
        setenv("HOME", target_home ? target_home : "/root", 1) != 0 ||
        setenv("SHELL", target_shell ? target_shell : "/bin/sh", 1) != 0) {
        free_kept(kept, kept_count);
        return -1;
    }

    for (size_t i = 0; i < kept_count; i++) {
        if (setenv(kept[i].name, kept[i].value, 1) != 0) {
            free_kept(kept, kept_count);
            return -1;
        }
    }

    free_kept(kept, kept_count);
    return 0;
}

int rise_drop_privs(const char *target_name, uid_t target_uid, gid_t target_gid) {
    if (!target_name) return -1;
    if (initgroups(target_name, target_gid) != 0) return -1;
    if (setresgid(target_gid, target_gid, target_gid) != 0) return -1;
    if (setresuid(target_uid, target_uid, target_uid) != 0) return -1;
    if (getuid() != target_uid || geteuid() != target_uid) return -1;
    if (getgid() != target_gid || getegid() != target_gid) return -1;
    return 0;
}

void rise_log_decision(const char *caller, const char *target, const char *command,
                       const char *result, const char *reason) {
    openlog("rise", LOG_PID, LOG_AUTHPRIV);
    syslog(LOG_NOTICE, "caller=%s target=%s command=%s result=%s reason=%s",
           caller ? caller : "?", target ? target : "?", command ? command : "?",
           result ? result : "?", reason ? reason : "?");
    closelog();
}

int rise_pam_auth(const char *service, const char *user, int attempts, int noninteractive, int jokes) {
    if (!service || !user) return -1;
    if (attempts <= 0 || attempts > 10) attempts = 3;
    if (noninteractive) return 2;

    for (int i = 0; i < attempts; i++) {
        pam_handle_t *pamh = NULL;
        struct pam_conv conv = { misc_conv, NULL };

        int ret = pam_start(service, user, &conv, &pamh);
        if (ret != PAM_SUCCESS) return -1;

        pam_set_item(pamh, PAM_RUSER, user);
        char *tty = ttyname(STDIN_FILENO);
        if (!tty) tty = ttyname(STDERR_FILENO);
        if (tty) pam_set_item(pamh, PAM_TTY, tty);

        ret = pam_authenticate(pamh, 0);
        if (ret == PAM_SUCCESS) {
            ret = pam_acct_mgmt(pamh, 0);
            pam_end(pamh, ret);
            return ret == PAM_SUCCESS ? 0 : -1;
        }

        pam_end(pamh, ret);

        if (jokes && i + 1 < attempts) {
            size_t n = sizeof(wrong_jokes) / sizeof(wrong_jokes[0]);
            fprintf(stderr, "rise: %s\n", wrong_jokes[pick_index(n, i)]);
        }
    }

    if (jokes) {
        size_t n = sizeof(final_jokes) / sizeof(final_jokes[0]);
        fprintf(stderr, "rise: %s\n", final_jokes[pick_index(n, attempts)]);
    }

    return 1;
}

static uint64_t fnv1a64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
    return h;
}

static int tty_scope_from_fd(int fd, char *out, size_t outsz) {
    if (fd < 0 || !out || outsz == 0) return -1;
    if (!isatty(fd)) return -1;

    struct stat fd_st;
    if (fstat(fd, &fd_st) != 0) return -1;
    if (!S_ISCHR(fd_st.st_mode)) return -1;

    char tty_path[PATH_MAX];
    tty_path[0] = '\0';

#if defined(_POSIX_VERSION)
    if (ttyname_r(fd, tty_path, sizeof(tty_path)) != 0) {
        tty_path[0] = '\0';
    }
#endif

    pid_t parent = getppid();
    pid_t sid = getsid(0);

    int n = snprintf(out, outsz,
                     "terminal-shell-v4:"
                     "fddev=%llu:fdino=%llu:fdrdev=%llu:"
                     "path=%s:"
                     "ppid=%ld:sid=%ld",
                     (unsigned long long)fd_st.st_dev,
                     (unsigned long long)fd_st.st_ino,
                     (unsigned long long)fd_st.st_rdev,
                     tty_path[0] ? tty_path : "unknown",
                     (long)parent,
                     (long)sid);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

static int ticket_scope(char *out, size_t outsz, int tty_tickets, int require_tty) {
    (void)require_tty;

    if (!out || outsz == 0) return -1;

    if (!tty_tickets) {
        int n = snprintf(out, outsz, "global");
        return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
    }

    if (tty_scope_from_fd(STDIN_FILENO, out, outsz) == 0) return 0;
    if (tty_scope_from_fd(STDOUT_FILENO, out, outsz) == 0) return 0;
    if (tty_scope_from_fd(STDERR_FILENO, out, outsz) == 0) return 0;

    return -2;
}

static int ticket_path(uid_t caller_uid, uid_t target_uid, int tty_tickets, int require_tty,
                       char *out, size_t outsz, uint64_t *scope_hash_out) {
    char scope[512];
    int s = ticket_scope(scope, sizeof(scope), tty_tickets, require_tty);
    if (s != 0) return s;

    uint64_t h = fnv1a64(scope);
    if (scope_hash_out) *scope_hash_out = h;

    int n = snprintf(out, outsz, "%s/u%lu-t%lu-%016llx",
                     RISE_TICKET_DIR,
                     (unsigned long)caller_uid,
                     (unsigned long)target_uid,
                     (unsigned long long)h);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

int rise_ticket_check(uid_t caller_uid, uid_t target_uid, int tty_tickets,
                      unsigned int timeout_seconds, int require_tty) {
    if (timeout_seconds == 0) return 1;
    if (ensure_ticket_dirs() != 0) return -1;

    char path[512];
    uint64_t scope_hash = 0;
    int tp = ticket_path(caller_uid, target_uid, tty_tickets, require_tty, path, sizeof(path), &scope_hash);
    if (tp != 0) return tp;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 1;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 1; }

    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        return 1;
    }

    char buf[160];
    ssize_t got = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (got <= 0) return 1;
    buf[got] = '\0';

    unsigned long ru = 0, tu = 0;
    unsigned long long rh = 0;
    if (sscanf(buf, RISE_TICKET_VERSION " %lu %lu %llx", &ru, &tu, &rh) != 3) return 1;
    if (ru != (unsigned long)caller_uid || tu != (unsigned long)target_uid || rh != (unsigned long long)scope_hash) return 1;

    time_t now = time(NULL);
    if (now == (time_t)-1) return 1;
    if (st.st_mtime > now) return 1;

    unsigned long age = (unsigned long)(now - st.st_mtime);
    return age <= timeout_seconds ? 0 : 1;
}

static int fsync_ticket_dir(void) {
    int dfd = open(RISE_TICKET_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return -1;
    int r = fsync(dfd);
    close(dfd);
    return r;
}

int rise_ticket_update(uid_t caller_uid, uid_t target_uid, int tty_tickets, int require_tty) {
    if (ensure_ticket_dirs() != 0) return -1;

    char path[512];
    uint64_t scope_hash = 0;
    int tp = ticket_path(caller_uid, target_uid, tty_tickets, require_tty, path, sizeof(path), &scope_hash);
    if (tp != 0) return tp;

    char tmp[600];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (tn < 0 || (size_t)tn >= sizeof(tmp)) return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        unlink(tmp);
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd);
        unlink(tmp);
        return -1;
    }

    if (fchown(fd, 0, 0) != 0 || fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }

    char buf[160];
    int n = snprintf(buf, sizeof(buf), RISE_TICKET_VERSION " %lu %lu %016llx\n",
                     (unsigned long)caller_uid,
                     (unsigned long)target_uid,
                     (unsigned long long)scope_hash);
    if (n < 0 || (size_t)n >= sizeof(buf)) { close(fd); unlink(tmp); return -1; }

    ssize_t wr = write(fd, buf, (size_t)n);
    if (wr != n) { close(fd); unlink(tmp); return -1; }

    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) != 0) { unlink(tmp); return -1; }

    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    (void)fsync_ticket_dir();
    return 0;
}

int rise_ticket_invalidate(uid_t caller_uid, uid_t target_uid, int tty_tickets) {
    if (ensure_ticket_dirs() != 0) return -1;

    char path[512];
    int tp = ticket_path(caller_uid, target_uid, tty_tickets, 0, path, sizeof(path), NULL);
    if (tp != 0) return tp;

    if (unlink(path) != 0 && errno != ENOENT) return -1;
    (void)fsync_ticket_dir();
    return 0;
}
