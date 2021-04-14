#include <stdio.h>
#include <mosquitto.h>
#include "../lib/mqtt.h"

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
