/**
 * Server side script which runs the authentication method. Functionalities
 * - Challenge creation
 * - Recreate EC sign from client
 * - Verify EC sign using client pub key and challenge hash
 * @author Sergio Garcia https://github.com/sergiogp98
 * @version v1.0
 */

#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "../include/crypt.h"
#include "../include/ecdsa.h"
#include "../include/utils.h"
#include "../include/mqtt.h"
#include "../include/uuid.h"
#include "../include/ssl.h"
#include "../include/conf.h"

#define ANUBIS "/home/%s/.anubis/%s.pub"
#define UUID_CSV "/etc/anubis/uuid.csv"
#define CONF_FILE "/etc/anubis/anubis.conf"

// Global vars

static int verify = 0;
static char challenge[CHALLENGE_SIZE];
static char username[MAX_USERNAME_LEN];
static char uuid[UUID_STR_LEN];
int get_r_value = 0;
int get_s_value = 0;
struct EC_SIGN sign;

/**
 * Callback function which run whenever a message is received from a subscribed topic
 * @param mosq mosquitto instance making the callback
 * @param obj user data provided in mosquitto_new
 * @param message the message data
 */
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	bool match_r_value_topic;
	bool match_s_value_topic;
	static char challenge_hash[HASH_SIZE];
	static char pemfile[MAX_PATH_LEN];
	ECDSA_SIG *signature;
	EC_KEY *pub_key;

	mosquitto_topic_matches_sub("+/pam/r", message->topic, &match_r_value_topic);
	mosquitto_topic_matches_sub("+/pam/s", message->topic, &match_s_value_topic);

	if (match_r_value_topic)
	{
		// Initialize ec_sign values
		sign.r = calloc(message->payloadlen, sizeof(char));
		strcpy(sign.r, (char *)message->payload);
		get_r_value = 1;
	}

	if (match_s_value_topic)
	{
		sign.s = calloc(message->payloadlen, sizeof(char));
		strcpy(sign.s, (char *)message->payload);
		get_s_value = 1;
	}

	if (get_r_value && get_s_value) // Client has sent EC signature
	{
		set_buffer(challenge_hash, HASH_SIZE, sha512(challenge));

		if ((signature = get_ec_sig(sign.r, sign.s)) != NULL)
		{
			sprintf(pemfile, ANUBIS, username, uuid);
			pub_key = get_pub_key_from_pem(pemfile); // Get Pub-key from pem file in user .anubis directory
			if (pub_key != NULL)
			{
				verify = ECDSA_do_verify(challenge_hash, HASH_SIZE, signature, pub_key);
				switch (verify)
				{
				case -1:
					fprintf(stderr, "Verification error\n");
					break;
				case 0:
					fprintf(stderr, "Invalid signature\n");
					break;
				default:
					printf("Successfully verified\n");
					break;
				}
				stop_mosq(mosq);
			}
		}
	}
}

/**
 * Link which function to use when using a specific callback
 * @param mosq mosquitto instance making the callback
 */
void set_callbacks(struct mosquitto *mosq)
{
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
}

/**
 * Start server function
 * @param mosq mosquitto instance
 * @return status of publishing challenge to specific topic
 */
int server_start(struct mosquitto *mosq)
{
	int retval = 0;
	struct mosquitto_message *messages;
	static char get_r_topic[TOPIC_SIZE];
	static char get_s_topic[TOPIC_SIZE];
	static char send_challenge_topic[TOPIC_SIZE];

	// Initialize challenge topics
	set_topic(get_r_topic, TOPIC_SIZE, uuid, "pam", "r");
	set_topic(get_s_topic, TOPIC_SIZE, uuid, "pam", "s");
	set_topic(send_challenge_topic, TOPIC_SIZE, "pam", uuid, "challenge");

	// Subscribe to ec sign values topics
	const char *topics[2] = {get_r_topic, get_s_topic};
	mosquitto_subscribe_multiple(mosq, NULL, 2, (char *const *const)topics, QoS, 0, NULL);

	// Create challenge
	set_buffer(challenge, CHALLENGE_SIZE, get_challenge());

	// Send challenge
	retval = mosquitto_publish(mosq, NULL, send_challenge_topic, CHALLENGE_SIZE, challenge, QoS, false);
	if (retval != MOSQ_ERR_SUCCESS)
	{
		fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_publish", send_challenge_topic, retval, mosquitto_strerror(retval));
	}

	return retval;
}

/**
 * PAM authenticate module hook function. Whenever a client request to open a SSH session, this function is executed
 * @param pamh PAM handler
 * @param flags optional flag
 * @param argc number of arguments
 * @param argv array of arguments 
 * @return PAM_SUCCESS if verification is correct (strict policy)
 * @return PAM_IGNORE if client comes from trusted IP address (relax policy)
 * @return PAM_AUTH_ERR if verification fails (strict policy) 
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	if (argc != 3)
    {
        fprintf(stderr, "Usage: ./server <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <CA_FILE>\n");
        return 1;
    }

	const char *pam_user;
	char server_id[ID_SIZE];
	char broker_host[MAX_HOSTNAME_LEN];
	int broker_port = 0;
	struct mosquitto *server = NULL;
	int retval = PAM_AUTH_ERR;
	char cafile[MAX_PATH_LEN];
	struct USER_UUID data;
	struct CONF_PARAMS params;
	
	// Save broker host and port
	set_buffer(broker_host, ID_SIZE, argv[0]);
	broker_port = atoi(argv[1]);

	// Save ca file
	set_buffer(cafile, MAX_PATH_LEN, argv[2]);

	// Get username
	pam_get_user(pamh, &pam_user, "Username: ");
	set_buffer(username, MAX_USERNAME_LEN, pam_user);

	// Get UUID from username
	if (get_uuid(UUID_CSV, username, &data))
	{
		set_buffer(uuid, UUID_STR_LEN, data.uuid);
		printf("Found UUID in user %s: %s\n", username, uuid);

		// Get config params
		if (read_conf(CONF_FILE, &params) == -1)
		{
			fprintf(stderr, "%s: invalid policy. Please use relax or strict\n", CONF_FILE);
			exit(1);
		}

		mosquitto_lib_init();
		
		set_id(server_id, ID_SIZE, "server");
		server = mosquitto_new(server_id, true, NULL);
		if (server)
		{
			// Set TLS connection
			if (set_tls_connection(server, cafile) == MOSQ_ERR_SUCCESS)
			{
				set_callbacks(server);
				if (connect_to_broker(server, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
				{
					if (server_start(server) == MOSQ_ERR_SUCCESS)
					{
						mosquitto_loop_start(server);
						mosquitto_loop_forever(server, -1, 1);
						
						if (verify != 1) // Not verified
						{
							if (params.access_type == 0) // Relax access
							{
								retval = PAM_IGNORE;
								printf("PAM IGNORE\n");
							}
							else // Strict access
							{
								retval = PAM_AUTH_ERR;
								printf("PAM_AUTH_ERR");
							}
						}
						else // Verified
						{
							retval = PAM_SUCCESS;
							printf("PAM_SUCCESS\n");
						}
					}
					else
					{
						fprintf(stderr, "Unable to start server\n");
					}
				}
				else
				{
					fprintf(stderr, "Unable to connect to broker\n");
				}
			}
			mosquitto_destroy(server);
		}
		else
		{
			perror("mosquitto_new");
		}

		mosquitto_lib_cleanup();
	}
	else
	{
		fprintf(stderr, "User %s has not an UUID assigned\n", username);
	}

	return retval;
}