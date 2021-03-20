#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "../lib/crypt.h"

// Global vars

#define KEEPALIVE 60
#define PAYLOAD_SIZE 65
#define CLIENT_ID_SIZE 24
#define QoS 0
#define SEND_CHALLENGE_TOPIC "pam/client/challenge"
#define RECEIVE_HASH_TOPIC "client/pam/hash"

// Mosquitto connect callback
void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	printf("%s = %d %s\n", "mosquitto_connect", result, mosquitto_strerror(result));
}

// Mosquitto subscribe callback
int subscribe_simple_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	printf("%s %s\n", (char *)message->topic, (char *)message->payload);
}

// Mosquitto publish callback
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	printf("Send %s to %s\n", (char *)message->payload, message->topic);
} 

// Mosquitto log callback
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

// Mosquitto publish callback
void publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
	printf("Published message %d\n", mid);
}

// Set mosquitto instance to callbacks
void set_callbacks(struct mosquitto *mosq, const char *host, const int port)
{
	mosquitto_connect_callback_set(mosq, connect_callback);
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
	mosquitto_publish_callback_set(mosq, publish_callback);
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
		set_callbacks(mosq, host, port);
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

	struct mosquitto *server;
	struct mosquitto_message *client_hash;
	char *server_hash;
	int retval = 0;
	char *broker_host = argv[1];
	int broker_port = atoi(argv[2]);
	char *challenge = get_challenge();
	int challenge_size = get_challenge_size();

	printf("challenge: %s\n", challenge); 
	printf("size of challenge: %d\n", challenge_size);

	mosquitto_lib_init();

	server = create_instance(create_id("server"), broker_host, broker_port);
	retval = mosquitto_connect(server, broker_host, broker_port, KEEPALIVE);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		retval = mosquitto_publish(server, NULL, SEND_CHALLENGE_TOPIC, challenge_size, challenge, QoS, false);
		if (retval == MOSQ_ERR_SUCCESS)
		{
			retval = mosquitto_subscribe_simple(
				&client_hash, true, true, RECEIVE_HASH_TOPIC, QoS, broker_host, broker_port, NULL,
				KEEPALIVE, true, NULL, NULL, NULL, NULL);
			if (client_hash != NULL)
			{
				server_hash = sha512(challenge);
				printf("server_hash: %s\n", server_hash);
				printf("client_hash: %s\n", (char *)client_hash->payload);
				if (!strcmp((char *)client_hash->payload, server_hash))
				{
					printf("Hashes match!\n");
				}
				else
				{
					fprintf(stderr, "Hashes do not match\n");
					return 1;
				}
			}
			else
			{
				fprintf(stderr, "%s = %d %s\n", "mosquitto_subscribe_simple", retval, mosquitto_strerror(retval));
				return 1;
			}	
		}
		else
		{
			fprintf(stderr, "%s = %d %s\n", "mosquitto_subscribe_simple", retval, mosquitto_strerror(retval));
			return 1;
		}
	}
	else 
	{
		fprintf(stderr, "%s = %d %s\n", "mosquitto_subscribe_simple", retval, mosquitto_strerror(retval));
		return 1;
	}
	
	mosquitto_lib_cleanup();

	return 0;
}
