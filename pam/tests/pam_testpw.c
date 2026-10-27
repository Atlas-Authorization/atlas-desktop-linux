/* Test-only stand-in for pam_unix: checks the AUTHTOK the harness set against a fixed password. Never installed. */
#include <string.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)flags; (void)argc; (void)argv;
  const char *pw = NULL;
  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pw) != PAM_SUCCESS || !pw) return PAM_AUTH_ERR;
  return strcmp(pw, "atlas-test-password") == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS; }
