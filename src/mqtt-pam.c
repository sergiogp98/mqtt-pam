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
#include "../include/file.h"

#define ANUBIS "/home/%s/.anubis/%s.pub"
#define UUID_CSV "/etc/anubis/uuid.csv"

// Global vars

static int verify = 0;
static char challenge[CHALLENGE_SIZE];
static char username[MAX_USERNAME_LEN];
static char uuid[UUID_STR_LEN];
int get_r_value = 0;
int get_s_value = 0;
struct EC_SIGN sign;

// Mosquitto message callback
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

void set_callbacks(struct mosquitto *mosq)
{
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
}

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

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: ./server <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT>\n");
		return PAM_ABORT;
	}

	const char *pam_user;
	char server_id[ID_SIZE];
	char broker_host[MAX_HOSTNAME_LEN];
	int broker_port = 0;
	struct mosquitto *server = NULL;
	int retval = PAM_AUTH_ERR;

	// Save broker host and port
	set_buffer(broker_host, ID_SIZE, argv[0]);
	broker_port = atoi(argv[1]);

	// Get username
	pam_get_user(pamh, &pam_user, "Username: ");
	set_buffer(username, MAX_USERNAME_LEN, pam_user);

	// Get UUID from username
	set_buffer(uuid, UUID_STR_LEN, get_uuid(UUID_CSV, username));

	if (uuid != NULL)
	{
		printf("Found UUID in user %s: %s\n", username, uuid);

		mosquitto_lib_init();

		set_id(server_id, ID_SIZE, "server");
		server = mosquitto_new(server_id, true, NULL);
		if (server)
		{
			set_callbacks(server);
			if (connect_to_broker(server, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
			{
				if (server_start(server) == MOSQ_ERR_SUCCESS)
				{
					mosquitto_loop_start(server);
					mosquitto_loop_forever(server, -1, 1);
					if (verify != 1)
					{
						printf("PAM DENY\n");
					}
					else
					{
						printf("PAM OK\n");
						retval = PAM_SUCCESS;
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

			mosquitto_destroy(server);
		}
		else
		{
			perror("mosquitto_new");
		}
	}
	else
	{
		fprintf(stderr, "User %s has not and UUID assigned\n", username);
	}

	mosquitto_lib_cleanup();

	return retval;
}