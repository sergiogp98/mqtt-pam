#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE 65
#define KEEPALIVE 60
#define QoS 0
#define CLIENT_ID_SIZE 24
#define SECRET_WORD_PATH "./secret-word.txt"
#define SEND_HASH_TOPIC "client/broker/hash"
#define RECEIVE_CHALLENGE_TOPIC "broker/client/challenge"
#include "../lib/sha256.h"

// Mosquitto subscribe callback
int subscribe_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	printf("%s %s\n", message->topic, (char *)message->payload);
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

// Mosquitto connect callback
void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	fprintf(stderr, "%s = %d %s\n", "mosquitto_connect", result, mosquitto_strerror(result));
}

// Set mosquitto instance to callbacks
void set_callbacks(struct mosquitto *mosq, const char *host, const int port)
{
	mosquitto_connect_callback_set(mosq, connect_callback);
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

    struct mosquitto_message *challenge;
    struct mosquitto *client;
	int retval = 0;
	char *broker_host = argv[1];
	int broker_port = atoi(argv[2]);
    char *secret = read_secret(SECRET_WORD_PATH);
    
    mosquitto_lib_init();

    client = create_instance(create_id("client"), broker_host, broker_port);
    retval = mosquitto_connect(client, broker_host, broker_port, KEEPALIVE);

    if (retval == MOSQ_ERR_SUCCESS)
    {
        retval = mosquitto_subscribe_simple(
            &challenge, true, true, RECEIVE_CHALLENGE_TOPIC, QoS, broker_host, broker_port, NULL,
            KEEPALIVE, true, NULL, NULL, NULL, NULL);

        if (retval != MOSQ_ERR_SUCCESS) 
        {
            printf("%s = %d %s\n", "mosquitto_subscribe_simple", retval, mosquitto_strerror(retval));
            return 1;
        }
        else {
            printf("Got challenge from server: %s\n", (char *)challenge->payload);
            char *hash = sha(secret, (char *)challenge->payload);
            printf("Challenge's hash: %s\n", hash);
            if (hash[0] != 0)
            {
                retval = mosquitto_publish(client, NULL, SEND_HASH_TOPIC, get_hash_size(), hash, QoS, false);
                if (retval != MOSQ_ERR_SUCCESS)
                {
                    printf("%s = %d %s\n", "mosquitto_publish", retval, mosquitto_strerror(retval));
                    return 1;   
                }
            }
            else
            {
                return 1;
            }
            
        }
        mosquitto_lib_cleanup();

    	return 0;
    }
}
