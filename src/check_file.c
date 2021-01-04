#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>   // stat
#define SERVICE_NAME "check_file"
#define FILE "/etc/ssh/sshd_config"
static struct pam_conv conv = { misc_conv, NULL };

int pam_check_file(char *filename) {
  struct stat buffer;
  int retval;

	if (stat(filename, &buffer) == 0) {
    retval = PAM_SUCCESS;
  } else {
    retval = PAM_ABORT;   
  }

  return retval;
}

int main(int argc, char *argv[]) 
{
  pam_handle_t *pamh;
  int result;
  struct passwd *pw;
  
  if ((pw = getpwuid(getuid( ))) == NULL)
    perror("getpwuid");
  else if ((result = pam_start(SERVICE_NAME, pw->pw_name, &conv, &pamh)) != PAM_SUCCESS)
    fprintf(stderr, "start failed: %d\n", result);
  else if ((result = pam_authenticate(pamh, 0)) != PAM_SUCCESS)
    fprintf(stderr, "authenticate failed: %d\n", result);
  else if ((result = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS)
    fprintf(stderr, "acct_mgmt failed: %d\n", result);
  else if ((result = pam_end(pamh, result)) != PAM_SUCCESS)
    fprintf(stderr, "end failed: %d\n", result);
  else
    printf("TEST");
    //if ((result = pam_check_file(FILE)) != PAM_SUCCESS)
    //  fprintf(stderr, "pam_check_file failed: %d\n", result);
}