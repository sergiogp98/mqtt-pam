#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// Global vars

#define KEEPALIVE 60
#define PAYLOAD_SIZE 65
#define CLIENT_ID_SIZE 24
#define QoS 0
#define SECRET_WORD_PATH "./secret-word.txt"
#define SEND_CHALLENGE_TOPIC "server/broker/challenge"
#define RECEIVE_HASH_TOPIC "broker/server/hash"
#include "../lib/sha256.h"

// Manage signal
void signal_handler(int sig)
{
	printf("You have presses Ctrl-C. Destroying mosquitto instance...");
}

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

	struct mosquitto_message *hash;
	struct mosquitto *server;
	int retval = 0;
	char *broker_host = argv[1];
	int broker_port = atoi(argv[2]);
	char *challenge = get_salt();
	int challenge_size = get_salt_size();
	char *secret = read_secret(SECRET_WORD_PATH);

	printf("challenge: %s\n", challenge); 
	printf("size of challenge: %d\n", challenge_size);
	printf("secret: %s\n", secret);
	
	mosquitto_lib_init();

	server = create_instance(create_id("server"), broker_host, broker_port);
	retval = mosquitto_connect(server, broker_host, broker_port, KEEPALIVE);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		retval = mosquitto_publish(server, NULL, SEND_CHALLENGE_TOPIC, challenge_size, challenge, QoS, false);
		if (retval == MOSQ_ERR_SUCCESS)
		{
			retval = mosquitto_subscribe_simple(
				&hash, true, true, RECEIVE_HASH_TOPIC, QoS, broker_host, broker_port, NULL,
				KEEPALIVE, true, NULL, NULL, NULL, NULL);
			if (hash != NULL)
			{
				if (!strcmp((char *)hash->payload, sha(secret, challenge)))
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
