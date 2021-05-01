/*******************************************************************************
 * file:        2ndfactor.c
 * author:      ben servoz
 * description: PAM module to provide 2nd factor authentication
 * notes:       instructions at http://ben.akrin.com/?p=1068
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "../include/mqtt.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse(pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response)
{
	int retval;
	struct pam_conv *conv;
	struct mosquitto *mosq;

	connect_to_broker(mosq, "broker.mqtt.com", 1883);
	//mosquitto_publish(mosq, NULL, "pam/debug", strlen("got it!"), "got it!", 1, false);
	retval =  (pamh, PAM_CONV, (const void **)&conv);
	if (retval == PAM_SUCCESS)
	{
		retval = conv->conv(nargs, (const struct pam_message **)message, response, conv->appdata_ptr);
	}

	return retval;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	int i;

	/* these guys will be used by converse() */
	char *input;
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;

	/* retrieving parameters */
	int got_base_url = 0;
	int got_code_size = 0;
	unsigned int code_size = 0;
	char base_url[256];
	for (i = 0; i < argc; i++)
	{
		if (strncmp(argv[i], "base_url=", 9) == 0)
		{
			strncpy(base_url, argv[i] + 9, 256);
			got_base_url = 1;
		}
		else if (strncmp(argv[i], "code_size=", 10) == 0)
		{
			char temp[256];
			strncpy(temp, argv[i] + 10, 256);
			code_size = atoi(temp);
			got_code_size = 1;
		}
	}
	if (got_base_url == 0 || got_code_size == 0)
	{
		return PAM_AUTH_ERR;
	}

	/* getting the username that was used in the previous authentication */
	const char *username;
	if ((retval = pam_get_user(pamh, &username, "login: ")) != PAM_SUCCESS)
	{
		return retval;
	}
	username = "garcapradossergi76";
	/* generating a random one-time code */
	char code[code_size + 1];
	unsigned int random_number;
	FILE *urandom = fopen("/dev/urandom", "r");
	fread(&random_number, sizeof(random_number), 1, urandom);
	fclose(urandom);
	snprintf(code, code_size + 1, "%u", random_number);
	code[code_size] = 0; // because it needs to be null terminated

	/* building URL */
	char url_with_params[strlen(base_url) + strlen("?username=") + strlen(username) + strlen("&code=") + code_size];
	strcpy(url_with_params, base_url);
	strcat(url_with_params, "?username=");
	strcat(url_with_params, username);
	strcat(url_with_params, "&code=");
	strcat(url_with_params, code);

	/* HTTP request to service that will dispatch the code */
	CURL *curl;
	CURLcode res;
	curl = curl_easy_init();
	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_URL, url_with_params);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	/* setting up conversation call prompting for one-time code */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_ON;
	msg[0].msg = "1-time code: ";
	resp = NULL;
	if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
	{
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval;
	}

	/* retrieving user input */
	if (resp)
	{
		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL)
		{
			free(resp);
			return PAM_AUTH_ERR;
		}
		input = resp[0].resp;
		resp[0].resp = NULL;
	}
	else
	{
		return PAM_CONV_ERR;
	}

	/* comparing user input with known code */
	if (strcmp(input, code) == 0)
	{
		/* good to go! */
		free(input);
		return PAM_SUCCESS;
	}
	else
	{
		/* wrong code */
		free(input);
		return PAM_AUTH_ERR;
	}

	/* we shouldn't read this point, but if we do, we might as well return something bad */
	return PAM_AUTH_ERR;
}
