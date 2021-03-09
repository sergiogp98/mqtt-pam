#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE 65
#define KEEPALIVE 60
#define QoS 0
#define COUNT 1


// Mosquitto return value handler
void return_handler(const char *function, int retval)
{
	printf("%s: %s\n", function, mosquitto_connack_string(retval));
}

// Mosquitto subscribe callback
int subscribe_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	for (int i = 0; i < COUNT; i++)
    {
        printf("%s %s\n", message[i].topic, (char *)message[i].payload);
    }
}

// Main
int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		fprintf(stderr, "Usage: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <TOPIC>\n");
		return 1;
	}

    struct mosquitto_message *challenge;
	int retval = 0;
	char *broker_host = argv[1];
	int broker_port = atoi(argv[2]);
	char *topic = argv[3];

    mosquitto_lib_init();
    mosquitto_subscribe_callback(
            subscribe_callback, 
            "challenge", 
            topic, 
            QoS, 
            broker_host,
            broker_port,
            NULL,
            KEEPALIVE, 
            true,
            NULL,
            NULL,
            NULL,
            NULL
        );
    retval = mosquitto_subscribe_simple(
        &challenge, COUNT, true, topic, QoS, broker_host, broker_port, NULL,
        KEEPALIVE, true, NULL, NULL, NULL, NULL);

    if (challenge == NULL) 
    {
        return_handler("mosquitto_subscribe_simple", retval);
        return 1;
    }
	mosquitto_lib_cleanup();

	return 0;
}
