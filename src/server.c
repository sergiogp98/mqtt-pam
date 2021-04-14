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

// Global vars

#define KEEPALIVE 60
#define TOPIC_SIZE 128
#define ID_SIZE 32
#define QoS 0
#define CLIENT_ID_TOPIC "client/pam/id"
#define GET_EC_PARAMS_TOPIC "+/pam/ec_params"

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

int server_start(struct mosquitto *mosq)
{
	int retval = 0;
	struct mosquitto_message *message;

	printf("Successfully start server\n");
	
	retval = mosquitto_subscribe(mosq, NULL, CLIENT_ID_TOPIC, QoS);
	if (retval != MOSQ_ERR_SUCCESS)
	{
		fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", CLIENT_ID_TOPIC, retval, mosquitto_strerror(retval));
	}
	else
	{
		printf("Listening to %s topic...\n", CLIENT_ID_TOPIC);
	}

	return retval;
}

// Mosquitto log callback
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
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
								verify = 1;
							}
							server_stop(mosq);
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

// Set mosquitto instance to callbacks
void set_callbacks(struct mosquitto *mosq, const char *host, const int port)
{
	mosquitto_message_callback_set(mosq, message_callback);
	//mosquitto_log_callback_set(mosq, log_callback);
}

int connect_to_broker(struct mosquitto *mosq, const char *broker_host, const int broker_port)
{
    int retval = 0;
	
	retval = mosquitto_connect(mosq, broker_host, broker_port, KEEPALIVE);
    if (retval == MOSQ_ERR_SUCCESS)
    {
		set_callbacks(mosq, broker_host, broker_port);
    }
	else
	{
		fprintf(stderr, "%s = %d %s\n", "mosquitto_connect", retval, mosquitto_strerror(retval));
	}

    return retval;
}

// Main
int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "Usage: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT>\n");
		return 1;
	}

	struct mosquitto *broker = NULL;
	int retval = 0;
	
	// Comprobacion host y port
	
	broker_host = argv[1];
	broker_port = atoi(argv[2]);
	
	mosquitto_lib_init();

	set_id(server_id, ID_SIZE, "server");
	broker = mosquitto_new(server_id, true, NULL);
	if (broker)
	{
		if (connect_to_broker(broker, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
		{
			if (server_start(broker) == MOSQ_ERR_SUCCESS)
			{
				mosquitto_loop_start(broker);
				mosquitto_loop_forever(broker, -1, 1);
				printf("Verify: %d\n", verify);
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
