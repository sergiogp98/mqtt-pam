#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "../lib/crypt.h"
#include "../lib/ecdsa.h"
#include "../lib/utils.h"
#include "../lib/mqtt.h"

// Global vars

static char *broker_host;
static int broker_port;
static char server_id[ID_SIZE];
static int verify = 0;

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
	bool topic_match = false;
	static char challenge[CHALLENGE_SIZE];
	static char challenge_hash[HASH_SIZE];
	static char client_id[ID_SIZE];
	static char send_challenge_topic[TOPIC_SIZE];
	static char get_ec_params_topic[TOPIC_SIZE];
	struct mosquitto_message *client_messages;
	EC_KEY *ec_key;
	ECDSA_SIG *signature;

	mosquitto_topic_matches_sub(CLIENT_ID_TOPIC, message->topic, &topic_match);

	if (topic_match) // Client want to connect 
	{
		printf("Received client ID: %s\n", (char *)message->payload);
		strcpy(client_id, (char *)message->payload);

		if (strlen(client_id) > 0)
		{
			//Initialize topics
			set_topic(send_challenge_topic, TOPIC_SIZE, "pam", client_id, "challenge");
			set_topic(get_ec_params_topic, TOPIC_SIZE, client_id, "pam", "ec_params");

			//Send challenge
			set_buffer(challenge, CHALLENGE_SIZE, get_challenge());
			retval = mosquitto_publish(mosq, NULL, send_challenge_topic, CHALLENGE_SIZE, challenge, QoS, false);
			if (retval == MOSQ_ERR_SUCCESS)
			{
				retval = mosquitto_subscribe_simple(
					&client_messages, 3, true, get_ec_params_topic, QoS, broker_host, 
					broker_port, server_id, KEEPALIVE, true, NULL, NULL, 
					NULL, NULL 
				);
				if (retval == MOSQ_ERR_SUCCESS)
				{
					set_buffer(challenge_hash, HASH_SIZE, sha512(challenge));
					const char *ec_point_hex = (char *)client_messages[0].payload;
					const char *r_hex = (char *)client_messages[1].payload;
					const char *s_hex = (char *)client_messages[2].payload; 

					if ((signature = get_ec_sig(r_hex, s_hex)) != NULL)
					{
						if ((ec_key = get_ec_key(ec_point_hex)) != NULL)
						{
							if (ECDSA_do_verify(challenge_hash, HASH_SIZE, signature, ec_key))
							{
								printf("PAM OK\n");
								verify = 1;
							}
							else
							{
								printf("PAM DENY\n");
							}
						}
					}
				}
				else
				{
					fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe_simple", get_ec_params_topic, retval, mosquitto_strerror(retval));
				}
			}
			else
			{
				fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_publish", send_challenge_topic, retval, mosquitto_strerror(retval));
			}
		}
		else
		{
			fprintf(stderr, "Bad client ID\n");
		}
	}
	else
	{
		fprintf(stderr, "Unknow topic: %s", message->topic);
	}
}  

int server_start(struct mosquitto *mosq)
{
	int retval = 0;
	struct mosquitto_message *message;

	printf("Successfully start server\n");
	
	retval = mosquitto_subscribe(mosq, NULL, CLIENT_ID_TOPIC, QoS);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		mosquitto_message_callback_set(mosq, message_callback);
		printf("Listening to %s topic...\n", CLIENT_ID_TOPIC);
	}
	else
	{
		fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", CLIENT_ID_TOPIC, retval, mosquitto_strerror(retval));
	}

	return retval;
}

// Main
int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "Usage: ./server <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT>\n");
		return 1;
	}

	struct mosquitto *server = NULL;
	int retval = 0;
	
	// Comprobacion host y port
	
	broker_host = argv[1];
	broker_port = atoi(argv[2]);
	
	mosquitto_lib_init();

	set_id(server_id, ID_SIZE, "server");
	server = mosquitto_new(server_id, true, NULL);
	if (server)
	{
		if (connect_to_broker(server, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
		{
			if (server_start(server) == MOSQ_ERR_SUCCESS)
			{
				mosquitto_loop_start(server);
				mosquitto_loop_forever(server, -1, 1);				
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
	
	mosquitto_lib_cleanup();

	return retval;
}
