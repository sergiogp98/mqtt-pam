//https://gist.github.com/evgeny-boger/8cefa502779f98efaf24

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <mosquitto.h>
#include <errno.h>

#define RECEIVE_CHALLENGE_TOPIC "server/broker/challenge"
#define RECEIVE_HASH_TOPIC "client/broker/hash"
#define SEND_CHALLENGE_TOPIC "broker/client/challenge"
#define SEND_HASH_TOPIC "broker/server/hash"
#define MQTT_HOST "localhost"
#define MQTT_PORT 1883
#define KEEPALIVE 60
#define QoS 1
#define MAX_RECONNECTION_COUNTS 10

void return_handler(const char *function, int retval)
{
	printf("%s: %s\n", function, mosquitto_connack_string(retval));
}

void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	return_handler("mosquitto_connect", result);
	if (result != MOSQ_ERR_SUCCESS)
	{
		int reconnection_count = 0;
		while (result != MOSQ_ERR_SUCCESS && reconnection_count < MAX_RECONNECTION_COUNTS)
		{
			fprintf(stderr, "Unable to connect (%d/%d). Reconnecting...\n", reconnection_count, MAX_RECONNECTION_COUNTS);
			reconnection_count += 1;
			result = mosquitto_reconnect(mosq);
		}

		if (reconnection_count == MAX_RECONNECTION_COUNTS)
		{
			fprintf(stderr, "Could not connnect. Destroying instance...\n");
			mosquitto_destroy(mosq);
		}
	}
}

void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	bool match_dst_topic = 0;
	int retval = 0;

	mosquitto_topic_matches_sub("+/broker/+", message->topic, &match_dst_topic);

	if (match_dst_topic)
	{
		bool match_server_topic = 0;
		mosquitto_topic_matches_sub(RECEIVE_CHALLENGE_TOPIC, message->topic, &match_server_topic);
		if (match_server_topic)
		{
			printf("Got challenge from server: %s\n", (char *)message->payload);
			retval = mosquitto_publish(
				mosq,
				NULL,
				SEND_CHALLENGE_TOPIC,
				message->payloadlen,
				message->payload,
				message->qos,
				message->retain);
		}
		else
		{
			printf("Got hash from client: %s\n", (char *)message->payload);
			retval = mosquitto_publish(
				mosq,
				NULL,
				SEND_HASH_TOPIC,
				message->payloadlen,
				message->payload,
				message->qos,
				message->retain);
		}
		return_handler("mosquitto_publish", retval);
	}
}

void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

void subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	printf("Message %d subscribed to %d topic(s)\n", mid, qos_count);
}

void set_callbacks(struct mosquitto *mosq)
{
	mosquitto_connect_callback_set(mosq, connect_callback);
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
	mosquitto_subscribe_callback_set(mosq, subscribe_callback);
}

int initialize_broker(struct mosquitto *mosq, const char *topics[])
{
	int retval = 0;

	set_callbacks(mosq);
	retval = mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, KEEPALIVE);
	if (retval == MOSQ_ERR_SUCCESS)
	{
		//retval = mosquitto_subscribe_multiple(mosq, NULL, 4, (char *const *const)topics, QoS, 0, NULL);
		//mosquitto_subscribe(mosq, NULL, SEND_CHALLENGE_TOPIC, QoS);
		//mosquitto_subscribe(mosq, NULL, SEND_HASH_TOPIC, QoS);
		mosquitto_subscribe(mosq, NULL, RECEIVE_CHALLENGE_TOPIC, QoS);
		mosquitto_subscribe(mosq, NULL, RECEIVE_HASH_TOPIC, QoS);
	}
		
	return retval;
}

int main(int argc, char *argv[])
{
	struct mosquitto *broker;
	const char *topics[4] = {SEND_CHALLENGE_TOPIC, SEND_HASH_TOPIC, RECEIVE_CHALLENGE_TOPIC, RECEIVE_HASH_TOPIC};
	int retval = 0;

	mosquitto_lib_init();

	broker = mosquitto_new("broker", true, NULL);

	if (broker)
	{
		retval = initialize_broker(broker, topics);
		if (retval == MOSQ_ERR_SUCCESS)
		{
			mosquitto_loop_start(broker);
			mosquitto_loop_forever(broker, -1, 1);
			mosquitto_destroy(broker);
		}
		else
		{
				return_handler("intialize_broker", retval);
				return 1;
		}		
	}
	else
	{
		fprintf(stderr, "mosquitto_new: %s\n", strerror(errno));
		return 1;
	}

	mosquitto_lib_cleanup();

	return 0;
}
