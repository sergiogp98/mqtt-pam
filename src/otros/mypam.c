#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	if (strcmp(pUsername, "root") != 0) {
		printf("Non root auth\n");
	} else {
		printf("Root auth\n");
	}
	
	return PAM_SUCCESS;
}
