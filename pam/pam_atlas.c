/* pam_atlas.so for Linux-PAM: the Atlas step of a PAM auth stack (sshd, sudo, su, login, GDM, LightDM).
 *
 * It follows the module that checked the password (pam_unix, sssd, ...) and talks to atlas-pam-helper over a socketpair with
 * the line protocol in atlas_pam_core.h. A refusal anywhere is PAM_AUTH_ERR.
 *
 *   auth  required  pam_unix.so            # first: verifies the password and leaves it as PAM_AUTHTOK
 *   auth  required  pam_atlas.so           # then Atlas
 *
 * Arguments: helper=/path (still must be root-owned), no_password (run without an earlier password, e.g. sshd publickey +
 * keyboard-interactive; the helper then relies on the stack ahead of us). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "atlas_pam_core.h"

#ifdef ATLAS_PAM_TESTING
#define HELPER_PATH_DEFAULT "/nonexistent"
#else
#define HELPER_PATH_DEFAULT "/usr/libexec/atlas/atlas-pam-helper"
#endif
#define KILL_SWITCH "/etc/atlas/pam-disabled"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
  pam_handle_t *pamh;
  int fd; /* one socket, both directions */
  char buf[1024];
  size_t have;
} session;

static int write_all(int fd, const char *s, size_t n) {
  while (n) {
    ssize_t w = send(fd, s, n, MSG_NOSIGNAL); /* a dead helper must not SIGPIPE sshd or sudo */
    if (w < 0) { if (errno == EINTR) continue; return -1; }
    s += w; n -= (size_t)w;
  }
  return 0;
}

static int io_send(void *ctx, const char *line) {
  session *s = ctx;
  size_t n = strlen(line);
  if (n + 1 >= ATLAS_LINE_MAX) return -1;
  return write_all(s->fd, line, n) || write_all(s->fd, "\n", 1) ? -1 : 0;
}

static int io_recv(void *ctx, char *buf, size_t n, int timeout_ms) {
  session *s = ctx;
  for (;;) {
    char *nl = memchr(s->buf, '\n', s->have);
    if (nl) {
      size_t len = (size_t)(nl - s->buf);
      if (len >= n) return -1;
      memcpy(buf, s->buf, len);
      buf[len] = 0;
      memmove(s->buf, nl + 1, s->have - len - 1);
      s->have -= len + 1;
      return 0;
    }
    if (s->have >= sizeof s->buf) return -1;
    struct pollfd p = {.fd = s->fd, .events = POLLIN};
    int r = poll(&p, 1, timeout_ms);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) return -1; /* timeout or error */
    ssize_t got = read(s->fd, s->buf + s->have, sizeof s->buf - s->have);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) return -1; /* EOF: the helper died */
    s->have += (size_t)got;
  }
}

static void converse(pam_handle_t *pamh, int style, const char *msg, char *reply, size_t n) {
  const struct pam_conv *conv = NULL;
  if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv || !conv->conv) return;
  struct pam_message m = {.msg_style = style, .msg = msg};
  const struct pam_message *mp = &m;
  struct pam_response *resp = NULL;
  if (conv->conv(1, &mp, &resp, conv->appdata_ptr) == PAM_SUCCESS && resp) {
    if (reply && resp[0].resp) { strncpy(reply, resp[0].resp, n - 1); reply[n - 1] = 0; }
    if (resp[0].resp) { atlas_wipe(resp[0].resp, strlen(resp[0].resp)); free(resp[0].resp); }
    free(resp);
  } else if (reply) {
    reply[0] = 0;
  }
}

static void io_info(void *ctx, const char *msg) { converse(((session *)ctx)->pamh, PAM_TEXT_INFO, msg, NULL, 0); }

static int io_prompt(void *ctx, const char *msg, int echo, char *buf, size_t n) {
  buf[0] = 0;
  converse(((session *)ctx)->pamh, echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF, msg, buf, n);
  return buf[0] ? 0 : -1; /* an empty answer cancels */
}

/* Root-owned and not writable by others, in a root-owned directory that others cannot write either. */
static int root_owned(const struct stat *st, int dir) {
  return st->st_uid == 0 && !(st->st_mode & (S_IWGRP | S_IWOTH)) && (dir ? S_ISDIR(st->st_mode) : S_ISREG(st->st_mode));
}

#ifndef ATLAS_PAM_TESTING
static int trusted(const char *path) {
  struct stat st;
  if (lstat(path, &st) != 0 || !root_owned(&st, 0) || !(st.st_mode & S_IXUSR)) return 0;
  char dir[1024];
  strncpy(dir, path, sizeof dir - 1);
  dir[sizeof dir - 1] = 0;
  char *slash = strrchr(dir, '/');
  if (!slash) return 0;
  *slash = 0;
  return stat(dir, &st) == 0 && root_owned(&st, 1);
}
#endif

static int kill_switch_on(void) {
  struct stat st;
  return lstat(KILL_SWITCH, &st) == 0 && root_owned(&st, 0);
}

static void wait_child(pid_t pid) {
  for (int i = 0; i < 20; i++) {
    int st;
    pid_t r = waitpid(pid, &st, WNOHANG);
    if (r == pid || (r < 0 && errno != EINTR)) return;
    usleep(50000);
  }
  kill(pid, SIGKILL);
  int st;
  while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
}

/* fork+exec instead of posix_spawn so every inherited descriptor and signal disposition can be reset first. */
static pid_t spawn_helper(const char *helper, int child_fd, int parent_fd, char *const env[]) {
  pid_t pid = fork();
  if (pid != 0) return pid;
  close(parent_fd);
  if (dup2(child_fd, 0) < 0 || dup2(child_fd, 1) < 0) _exit(126);
  int nul = open("/dev/null", O_WRONLY);
  if (nul >= 0) dup2(nul, 2);
#ifdef SYS_close_range
  if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0)
#endif
    for (int fd = 3; fd < 1024; fd++) close(fd);
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = SIG_DFL;
  for (int sig = 1; sig < 32; sig++) if (sig != SIGKILL && sig != SIGSTOP) sigaction(sig, &sa, NULL);
  sigset_t none;
  sigemptyset(&none);
  sigprocmask(SIG_SETMASK, &none, NULL);
  char *args[] = {(char *)helper, (char *)"serve", NULL};
  execve(helper, args, env);
  _exit(127);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)flags;
  const char *helper = HELPER_PATH_DEFAULT;
  int no_password = 0;
  for (int i = 0; i < argc; i++) {
    if (!strncmp(argv[i], "helper=", 7)) helper = argv[i] + 7;
    else if (!strcmp(argv[i], "no_password")) no_password = 1;
  }
  const char *user = NULL, *service = NULL, *pw = NULL;
  if (kill_switch_on()) {
    pam_syslog(pamh, LOG_WARNING, "pam_atlas: kill switch present, Atlas step skipped");
    return PAM_IGNORE;
  }
  if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !atlas_valid_user(user)) return PAM_AUTH_ERR;
  if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || !atlas_valid_service(service)) return PAM_AUTH_ERR;
  /* The earlier module must have checked a password; without one we only go on when the admin said so. */
  if (!no_password && (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pw) != PAM_SUCCESS || !pw || !*pw)) {
    pam_syslog(pamh, LOG_NOTICE, "pam_atlas: no password from an earlier module for %s (%s); refused", user, service);
    return PAM_AUTH_ERR;
  }

#ifdef ATLAS_PAM_TESTING
  if (getenv("ATLAS_PAM_HELPER")) helper = getenv("ATLAS_PAM_HELPER");
#else
  if (!trusted(helper)) {
    pam_syslog(pamh, LOG_ERR, "pam_atlas: helper %s missing or not root-owned; refused", helper);
    return PAM_AUTH_ERR;
  }
#endif

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) return PAM_AUTH_ERR;
  char *env[3] = {(char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL, NULL};
#ifdef ATLAS_PAM_TESTING
  /* The fake helper picks its scenario from the environment; the real helper gets nothing but PATH. */
  char scenario[64];
  if (getenv("ATLAS_FAKE")) { snprintf(scenario, sizeof scenario, "ATLAS_FAKE=%s", getenv("ATLAS_FAKE")); env[1] = scenario; }
#endif
  pid_t pid = spawn_helper(helper, sv[1], sv[0], env);
  close(sv[1]);
  if (pid < 0) {
    pam_syslog(pamh, LOG_ERR, "pam_atlas: cannot start the helper (%s); refused", strerror(errno));
    close(sv[0]);
    return PAM_AUTH_ERR;
  }

  session s = {.pamh = pamh, .fd = sv[0]};
  atlas_io io = {.ctx = &s, .send = io_send, .recv = io_recv, .info = io_info, .prompt = io_prompt};
  int allowed = atlas_authenticate(&io, user, service);
  io_send(&s, "QUIT");
  shutdown(sv[0], SHUT_WR);
  close(sv[0]);
  wait_child(pid);
  atlas_wipe(s.buf, sizeof s.buf);
  pam_syslog(pamh, allowed ? LOG_INFO : LOG_NOTICE, "pam_atlas: %s for %s (%s)", allowed ? "allowed" : "refused", user, service);
  return allowed ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SERVICE_ERR; }
