#ifndef MQTT_H_
#define MQTT_H_

#define KEEPALIVE 60
#define TOPIC_SIZE 128
#define ID_SIZE 32
#define QoS 0
#define CLIENT_ID_TOPIC "client/pam/id"
#define CHALLENGE_TOPIC "pam/+/challenge"
#define GET_EC_PARAMS_TOPIC "+/pam/ec_params"
#define ENABLE_LOGS 1

#include <stdio.h>
#include <mosquitto.h>

// Mosquitto log callback
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

int connect_to_broker(struct mosquitto *mosq, const char *broker_host, const int broker_port)
{
    int retval = 0;

    retval = mosquitto_connect(mosq, broker_host, broker_port, KEEPALIVE);
    if (retval == MOSQ_ERR_SUCCESS)
    {
        if (ENABLE_LOGS)
        {
            mosquitto_log_callback_set(mosq, log_callback);
        }
    }
    else
    {
        fprintf(stderr, "%s = %d %s\n", "mosquitto_connect", retval, mosquitto_strerror(retval));
    }

    return retval;
}

void stop_mosq(struct mosquitto *mosq)
{
	printf("Exiting...\n");
	if (mosquitto_disconnect(mosq) != MOSQ_ERR_SUCCESS)
	{
		fprintf(stderr, "Unable to stop server\n");
	}
}

#endif
