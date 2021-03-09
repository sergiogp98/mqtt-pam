#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>

// Global vars

#define KEEPALIVE 60
#define PAYLOAD_SIZE 65
#define COMMAND_SIZE 100
#define QoS 0
#define SHA256_SCRIPT_PATH "../sha256.sh"
#define CHALLENGE_PATH "./hash.txt"
#define SEND_CHALLENGE_TOPIC "server/broker/challenge"
#define RECEIVE_HASH_TOPIC "broker/server/hash"

// Mosquitto return value handler
void return_handler(const char *function, int retval)
{
	printf("%s: %s\n", function, mosquitto_connack_string(retval));
}

// Write hash file
void get_payload(char payload[], const char *file)
{
	FILE *fp;
	fp = fopen(file, "r");
	fscanf(fp, "%s", payload);
	printf("payload: %s\n", payload);
}

// Execute sha256 script and return hash value
void sha256(char payload[])
{
	char command[COMMAND_SIZE];

	snprintf(command, COMMAND_SIZE, "bash %s | tail -1 | awk -F['='] '{print $2}' > %s", SHA256_SCRIPT_PATH, CHALLENGE_PATH);
	system(command);
	get_payload(payload, CHALLENGE_PATH);
}

// Mosquitto connect callback
void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	return_handler("mosquitto_connect", result);
}

// Mosquitto subscribe callback
void subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	printf("Subscribe callback, qos_count=%d\n", qos_count);
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

// Set mosquitto instance to callbacks
void set_callbacks(struct mosquitto *mosq, const char *host, const int port)
{
	mosquitto_connect_callback_set(mosq, connect_callback);
	mosquitto_subscribe_callback_set(mosq, subscribe_callback);
	mosquitto_subscribe_callback(
		subscribe_callback,
		"hash",
		RECEIVE_HASH_TOPIC,
		QoS,
		host,
		port,
		NULL,
		KEEPALIVE,
		true,
		NULL,
		NULL,
		NULL,
		NULL);
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
}

int initialize_broker(struct mosquitto *mosq, const char *host, const int port)
{
	int retval = 0;

	set_callbacks(mosq);
	retval = mosquitto_connect(mosq, host, port, KEEPALIVE);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		retval = mosquitto_subscribe(mosq, NULL, SEND_CHALLENGE_TOPIC, QoS);
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

	struct mosquitto *broker;
	int retval = 0;
	char *broker_host = argv[1];
	int broker_port = atoi(argv[2]);
	char payload[PAYLOAD_SIZE];
	sha256(payload);
	
	mosquitto_lib_init();

	broker = mosquitto_new("broker", true, NULL);

	if (broker)
	{	
		retval = initialize_broker(broker, broker_host, broker_port);
		if (retval == MOSQ_ERR_SUCCESS)
		{
			retval = mosquitto_publish(broker, NULL, SEND_CHALLENGE_TOPIC, sizeof(payload), payload, QoS, false);
			if (reval == MOSQ_ERR_SUCCESS)
			{
				struct mosquitto_message *hash;
				retval = mosquitto_subscribe_simple(
					&hash, 1, true, RECEIVE_HASH_TOPIC, QoS, broker_host, broker_port, NULL,
					KEEPALIVE, true, NULL, NULL, NULL, NULL);
				if (hash != NULL)
				{
					//Check hashes
				}
				else
				{
					return_handler("mosquitto_subscribe_simple", retval);
					return 1;
				}
			}
			else
			{
				return_handler("mosquitto_publish", retval);
				return 1;
			}
		}
		else 
		{
			return_handler("intialize_broker", retval);
			return 1;
		}
		
		
		mosquitto_loop_start(broker);
		mosquitto_loop_forever(broker, -1, 1);
		mosquitto_destroy(broker);
	}
	else
	{
		fprintf(stderr, "mosquitto_new: %s\n", strerror(errno));
		return 1;
	}

	mosquitto_lib_cleanup();

	return 0;
}
