/* harness <service> <user> <password|-> [answer ...]
 * Runs pam_authenticate for the service through the real PAM stack. Answers feed the hidden prompts in order; messages are
 * printed as INFO lines. Exit 0 on PAM_SUCCESS, 1 on any other result. */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char **answers; int n, i; const char *pw; } script;

static int conv(int num, const struct pam_message **msg, struct pam_response **resp, void *data) {
  script *s = data;
  struct pam_response *r = calloc((size_t)num, sizeof *r);
  if (!r) return PAM_BUF_ERR;
  for (int k = 0; k < num; k++) {
    switch (msg[k]->msg_style) {
      case PAM_TEXT_INFO: case PAM_ERROR_MSG: printf("INFO:%s\n", msg[k]->msg); break;
      case PAM_PROMPT_ECHO_OFF: case PAM_PROMPT_ECHO_ON:
        /* The password module (pam_get_authtok) asks first, as in a real login; answer it quietly. */
        if (s->pw && !strncmp(msg[k]->msg, "Password", 8)) { r[k].resp = strdup(s->pw); s->pw = NULL; break; }
        printf("PROMPT:%s\n", msg[k]->msg);
        if (s->i >= s->n) { free(r); return PAM_CONV_ERR; }
        r[k].resp = strdup(s->answers[s->i++]);
        break;
      default: free(r); return PAM_CONV_ERR;
    }
  }
  *resp = r;
  return PAM_SUCCESS;
}

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: harness service user password|- [answers...]\n"); return 2; }
  script s = {.answers = argv + 4, .n = argc - 4, .pw = strcmp(argv[3], "-") ? argv[3] : NULL};
  struct pam_conv c = {conv, &s};
  pam_handle_t *h = NULL;
  int rc = pam_start(argv[1], argv[2], &c, &h);
  if (rc != PAM_SUCCESS) { printf("RESULT start=%d\n", rc); return 1; }
  rc = pam_authenticate(h, 0);
  printf("RESULT %d\n", rc);
  pam_end(h, rc);
  return rc == PAM_SUCCESS ? 0 : 1;
}
