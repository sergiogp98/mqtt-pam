//https://gist.github.com/evgeny-boger/8cefa502779f98efaf24

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <mosquitto.h>
#include <errno.h>

#define SERVER_TOPIC "/server/ssh"
#define CLIENT_TOPIC "/client/ssh"
#define MQTT_HOST "localhost"
#define MQTT_PORT 1883
#define KEEPALIVE 60
#define QoS 0
#define CLEAN_SESSION true
#define MAX_RECONNECTION_COUNTS 10


void return_handler(const char *function, int retval)
{
	printf("%s: %s\n", function, mosquitto_connack_string(retval));
}

void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
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

void publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
	printf("Successfully forward message %d\n", mid);
}

void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct mosquitto *forward = (struct mosquitto *)obj;
	bool match_server_topic = 0;
	int retval = 0;

	mosquitto_topic_matches_sub(SERVER_TOPIC, message->topic, &match_server_topic);
	mosquitto_loop_start(forward);

	if (match_server_topic)
	{
		printf("Got challenge from server: %s\n", (char *)message->payload);
		retval = mosquitto_publish(
			forward,
			NULL,
			CLIENT_TOPIC,
			message->payloadlen,
			message->payload,
			message->qos,
			message->retain);
	}
	else
	{
		printf("Got hash from client: %s", (char *)message->payload);
		retval = mosquitto_publish(
			forward,
			NULL,
			SERVER_TOPIC,
			message->payloadlen,
			message->payload,
			message->qos,
			message->retain);
	}
	return_handler("mosquitto_publish (receiver)", retval);

	mosquitto_disconnect(forward);
	mosquitto_loop_stop(forward, false);
}

void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

void set_callbacks(struct mosquitto *mosq, const char *id)
{
	mosquitto_log_callback_set(mosq, log_callback);
	mosquitto_connect_callback_set(mosq, connect_callback);
	if (!strcmp(id, "listener"))
	{
		mosquitto_message_callback_set(mosq, message_callback);
	}
	else
	{
		mosquitto_publish_callback_set(mosq, publish_callback);
	}
}

void initialise_mosquitto_instance(struct mosquitto *mosq, const char *id)
{
	set_callbacks(mosq, id);
	mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, KEEPALIVE);
	mosquitto_subscribe(mosq, NULL, SERVER_TOPIC, QoS);
	mosquitto_subscribe(mosq, NULL, CLIENT_TOPIC, QoS);
}

void create_mosquitto_instance(struct mosquitto *mosq, const char *id, void *obj) 
{
	char clientid[24];
	memset(clientid, 0, 24);
	snprintf(clientid, 23, "%s_%d", id, getpid());

	if (obj != NULL)
	{
		mosq = mosquitto_new(clientid, true, (struct mosquitto *)obj);
	}
	else 
	{
		mosq = mosquitto_new(clientid, true, NULL);
	}
}

int main(int argc, char *argv[])
{
	struct mosquitto *mosq;
	
	struct mosquitto *listener; // Mosquitto listener instance
	struct mosquitto *forwarder; // Mosquitto forwarder instance

	mosquitto_lib_init();

	create_mosquitto_instance(forwarder, "forwarder", NULL);
	create_mosquitto_instance(listener, "listener", forwarder);
	
	if (listener)
	{
		initialise_mosquitto_instance(listener, "listener");
		initialise_mosquitto_instance(forwarder, "forwarder");
		mosquitto_loop_start(listener);
		mosquitto_loop_forever(listener, -1, 1);
		mosquitto_destroy(listener);
	}
	else
	{
		fprintf(stderr, "mosquitto_new: %s\n", strerror(errno));
		return 1;
	}

	mosquitto_lib_cleanup();

	return 0;
}
