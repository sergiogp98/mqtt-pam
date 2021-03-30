#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <openssl/ecdsa.h>   // for ECDSA_do_verify
#include <openssl/ec.h>
#include "../lib/crypt.h"
typedef struct
{
	ECDSA_SIG *signature;
	EC_KEY *pub_key;
} Hash;

// Global vars

#define KEEPALIVE 60
#define TOPIC_SIZE 128
#define CLIENT_ID_SIZE 32
#define CHALLENGE_SIZE 64
#define QoS 0

static char client_id[CLIENT_ID_SIZE];
static char get_client_id_topic[TOPIC_SIZE];
static char get_hash_topic[TOPIC_SIZE];
static char send_challenge_topic[TOPIC_SIZE];
static char challenge[CHALLENGE_SIZE];

// Mosquitto log callback
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

// Mosquitto message callback
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	int retval = 0;

	if (strcmp(message->topic, get_client_id_topic) == 0) // Client want to connect 
	{
		printf("Received client ID: %s\n", (char *)message->payload);
		memset(client_id, 0, CLIENT_ID_SIZE);
		snprintf(client_id, CLIENT_ID_SIZE-1, "%s", (char *)message->payload);
		
		if (strlen(client_id) > 0)
		{
			//Initialize topics
			memset(send_challenge_topic, 0, TOPIC_SIZE);
			memset(get_hash_topic, 0, TOPIC_SIZE);
			snprintf(send_challenge_topic, TOPIC_SIZE-1, "pam/%s/challenge", client_id);
			snprintf(get_hash_topic, TOPIC_SIZE-1, "%s/pam/hash", client_id);
			
			// Create challenge
			memset(challenge, 0, CHALLENGE_SIZE);
			snprintf(challenge, CHALLENGE_SIZE-1, "%s", get_challenge());
			
			//Send challenge
			printf("Send challenge to client: %s\n", challenge);
			retval = mosquitto_publish(mosq, NULL, send_challenge_topic, CHALLENGE_SIZE, challenge, QoS, false);
			if (retval == MOSQ_ERR_SUCCESS)
			{
				// Subscribe to hash topic
				retval = mosquitto_subscribe(mosq, NULL, get_hash_topic, QoS);
				if (retval != MOSQ_ERR_SUCCESS)
				{
					fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", get_hash_topic, retval, mosquitto_strerror(retval));
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
	else if (strcmp(message->topic, get_hash_topic) == 0) // signature + pubkey
	{
		Hash *ec_item = (Hash*) &message->payload;
		const ECDSA_SIG *signature = (ECDSA_SIG *)ec_item->signature;
		EC_KEY *pub_key = (EC_KEY *)ec_item->pub_key;
		const char *hash = sha512(challenge);

		if (ECDSA_do_verify(hash, strlen(hash), signature, pub_key))
		{
			printf("Verifed EC Signature\n");
		}
		else
		{
			printf("Failed to verify EC Signature\n");
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
	mosquitto_log_callback_set(mosq, log_callback);
}

const char *create_id(const char *name)
{
    static char clientid[CLIENT_ID_SIZE];
    memset(clientid, 0, CLIENT_ID_SIZE);
    snprintf(clientid, CLIENT_ID_SIZE-1, "%s_%d", name, getpid());

    return clientid;
}

struct mosquitto *create_instance(const char *id, const char *host, const int port)
{
	struct mosquitto *mosq;
	mosq = mosquitto_new(id, true, NULL);

	if (mosq)
	{
		mosquitto_message_callback_set(mosq, message_callback);
		mosquitto_log_callback_set(mosq, log_callback);
	}
	else
	{
		perror("mosquitto_new");
	}

	return mosq;
}

// Main
int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "Usage: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT>\n");
		return 1;
	}

	struct mosquitto *broker;
	int retval = 0;
	char *broker_host = argv[1];
	int broker_port = atoi(argv[2]);
	
	// Comprobacion host y port

	mosquitto_lib_init();

	broker = create_instance(create_id("broker"), broker_host, broker_port);
	retval = mosquitto_connect(broker, broker_host, broker_port, KEEPALIVE);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		memset(get_client_id_topic, 0, TOPIC_SIZE);
		snprintf(get_client_id_topic, TOPIC_SIZE-1, "client/pam/id");
		retval = mosquitto_subscribe(broker, NULL, get_client_id_topic, QoS);
		if (retval == MOSQ_ERR_SUCCESS)
		{
			printf("Listening to %s topic...\n", get_client_id_topic);
		}
		else
		{
			fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", get_client_id_topic, retval, mosquitto_strerror(retval));
			return 1;
		}
	}
	else 
	{
		fprintf(stderr, "%s = %d %s\n", "mosquitto_connect", retval, mosquitto_strerror(retval));
		return 1;
	}
	
	mosquitto_loop_start(broker);
	mosquitto_loop_forever(broker, -1, 1);
	mosquitto_destroy(broker);

	mosquitto_lib_cleanup();

	return 0;
}
