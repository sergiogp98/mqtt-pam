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

// Global vars

#define BROKER_HOST "broker.mqtt.com"
#define BROKER_PORT 1883
#define UUID "21fb034c-c837-407a-a585-cee50ed9a74c"

static char server_id[ID_SIZE];
static int verify = 0;
static char *challenge = NULL;
static char *username = NULL;
static int get_r_value = 0;
static int get_s_value = 0;

int server_stop(struct mosquitto *mosq)
{
	int retval = 0;

	printf("Exiting...\n");
	if (mosquitto_disconnect(mosq) != MOSQ_ERR_SUCCESS)
	{
		fprintf(stderr, "Unable to stop server\n");
	}
						
	return retval;
}

// Mosquitto message callback
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	int retval = 0;
	int verified = 0;
	bool r_value_topic_match = false;
	bool s_value_topic_match = false;
	static char challenge_hash[HASH_SIZE];
	char *r_hex, *s_hex;
	ECDSA_SIG *signature;
	EC_KEY *pub_key;

	mosquitto_topic_matches_sub("+/pam/r", message->topic, &r_value_topic_match);
	mosquitto_topic_matches_sub("+/pam/s", message->topic, &s_value_topic_match);

	if (r_value_topic_match)
	{
		r_hex = (char *)message->payload;
		get_r_value = 1;
	}

	if (s_value_topic_match)
	{
		s_hex = (char *)message->payload;
		get_s_value = 1;
	}

	if (get_r_value && get_s_value) // Client has sent EC signature 
	{
		set_buffer(challenge_hash, HASH_SIZE, sha512(challenge));

		if ((signature = get_ec_sig(r_hex, s_hex)) != NULL)
		{
			if ((pub_key = get_pub_key(username)) != NULL) // Get Pub-key from pem file in user .anubis directory
			{
				if (ECDSA_do_verify(challenge_hash, HASH_SIZE, signature, pub_key))
				{
					printf("Successfully verified\n");
					verify = 1;
				}
				else
				{
					printf("Failed verification\n");
				}
				server_stop(mosq);
			}
		}
	}
}  

int server_start(struct mosquitto *mosq)
{
	int retval = 0;
	struct mosquitto_message *message;
	static char get_ec_sign_r_topic[TOPIC_SIZE];
	static char get_ec_sign_s_topic[TOPIC_SIZE];
	static char send_challenge_topic[TOPIC_SIZE];

	// Initialize challenge topics
	set_topic(get_ec_sign_r_topic, TOPIC_SIZE, UUID, "pam", "r");
	set_topic(get_ec_sign_s_topic, TOPIC_SIZE, UUID, "pam", "s");
	set_topic(send_challenge_topic, TOPIC_SIZE, "pam", UUID, "challenge");
	const char *topics[2] = {get_ec_sign_r_topic, get_ec_sign_s_topic};

	// Subscribe to ec_sign topic
	retval = mosquitto_subscribe_multiple(mosq, NULL, 2, (char *const *const)topics, QoS, NULL, NULL);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		// Create challenge
		set_buffer(challenge, CHALLENGE_SIZE, get_challenge());

		// Send challenge
		retval = mosquitto_publish(mosq, NULL, send_challenge_topic, CHALLENGE_SIZE, challenge, QoS, false);
		if (retval == MOSQ_ERR_SUCCESS)
		{
			retval = 1;
		}
		else
		{
			fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_publish", send_challenge_topic, retval, mosquitto_strerror(retval))
		}
	}
	else
	{
		fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", ec_sign_topic, retval, mosquitto_strerror(retval));
	}

	return retval;
}

// Main
int main(int argc, char *argv[])
{
	struct mosquitto *broker = NULL;
	int retval = 0;

	mosquitto_lib_init();

	set_id(server_id, ID_SIZE, "server");
	broker = mosquitto_new(server_id, true, NULL);
	if (broker)
	{
		if (connect_to_broker(broker, BROKER_HOST, BROKER_PORT) == MOSQ_ERR_SUCCESS)
		{
			if (server_start(broker) == MOSQ_ERR_SUCCESS)
			{
				mosquitto_loop_start(broker);
				mosquitto_loop_forever(broker, -1, 1);
				if (verify)
				{
					printf("PAM OK\n");
				}
				else
				{
					printf("PAM DENY\n");
				}
				retval = 1;
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

		mosquitto_destroy(broker);
	}
	else
	{
		perror("mosquitto_new");
	}
	
	mosquitto_lib_cleanup();

	return retval;
}