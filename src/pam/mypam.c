#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <mosquitto.h>
//#include "../include/server.h"
//#include "../include/crypt.h"
//#include "../include/ecdsa.h"
//#include "../include/utils.h"
//#include "../include/mqtt.h"

//static char server_id[ID_SIZE];


/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	int retval = PAM_AUTH_ERR;
	
	if (argc != 2)
	{
		printf("Usage: server <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT>\n");
		retval = PAM_AUTH_ERR;
	}

	if (retval != PAM_AUTH_ERR)
	{
		struct mosquitto *broker = NULL;
		const char *broker_host = argv[0];
		const int broker_port = atoi(argv[1]);
		//char *server_id = (char *)calloc(50, sizeof(int));

		printf("%s %d\n", broker_host, broker_port);

		//mosquitto_lib_init();
		//set_id(server_id, 50, "server");
		//printf("%s\n", server_id);
		//broker = mosquitto_new("server_54559", true, NULL);
		//if (broker != NULL)
		//{
		//	if (mosquitto_connect(broker, broker_host, broker_port, 60) == MOSQ_ERR_SUCCESS)
		//	{
		//		printf("success mosquitto_connect\n");
		//	}
		//	else
		//	{
		//		printf("error mosquitto_connect\n");
		//	}
		//}
		//else
		//{
		//	printf("error mosquitto_new\n");
		//}

		retval = PAM_SUCCESS;
	}

	return retval;
}
