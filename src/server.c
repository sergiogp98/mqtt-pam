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

// Env variables

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
				default: //1
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


int main(int argc, char *argv[])
{
	if (argc != 4)
    {
        fprintf(stderr, "Usage: ./server <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <CA_FILE>\n");
        return 1;
    }

	char server_id[ID_SIZE];
	char broker_host[MAX_HOSTNAME_LEN];
	int broker_port = 0;
    struct mosquitto *server = NULL;
    int retval;
	char cafile[MAX_PATH_LEN];
	struct USER_UUID data;
	struct CONF_PARAMS params;

    // Save broker host and port
    set_buffer(broker_host, ID_SIZE, argv[1]);
    broker_port = atoi(argv[2]);

	// Save ca file
	set_buffer(cafile, MAX_PATH_LEN, argv[3]);

	// Get UUID from username
	set_buffer(username, MAX_USERNAME_LEN, "client-1");
	if (get_uuid(UUID_CSV, username, &data))
	{
		set_buffer(uuid, UUID_STR_LEN, data.uuid);
		printf("Found UUID in user %s: %s\n", username, uuid);

		// Get config params
		if (!read_conf(CONF_FILE, &params))
		{
			fprintf(stderr, "Error reading %s file\n", CONF_FILE);
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
	}
	else
	{
		fprintf(stderr, "User %s has not and UUID assigned\n", username);
	}

	mosquitto_lib_cleanup();

	return retval;
}