#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>

static struct pam_conv conv = {
    misc_conv, /* Conversation function defined in pam_misc.h */
    NULL       /* We don't need additional data now*/
};

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    int retval;
    char *username; /* This will be set by PAM with pam_get_item (see below) */

    retval = pam_authenticate(handle, 0); /* Do authentication (user will be asked for username and password)*/
    if (retval != PAM_SUCCESS)
    {
        fprintf(stderr, "Failure in pam authentication: %s", pam_strerror(handle, retval));
    }

    retval = pam_acct_mgmt(handle, 0); /* Do account management (check the account can access the system) */
    if (retval != PAM_SUCCESS)
    {
        fprintf(stderr, "Failure in pam account management: %s", pam_strerror(handle, retval));
    }

    /* We now get the username given by the user */
    pam_get_item(handle, PAM_USER, (const void **)&username);
    printf("WELCOME, %s\n", username);

    printf("Do you want to change your password? (answer y/n): ");
    char answer = getc(stdin); /* Taking user answer */
    if (answer == 'y')
    {
        retval = pam_chauthtok(handle, 0); /* Do update (user will be asked for current and new password) */
        if (retval != PAM_SUCCESS)
        {
            fprintf(stderr, "Failure in pam password: %s", pam_strerror(handle, retval));
        }
    }

    pam_end(handle, retval); /* ALWAYS terminate the pam transaction!! */

    return retval;
}