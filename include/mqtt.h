/**
 * Header file with functions related with MQTT
 */

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
#include <time.h>
#include <unistd.h>
#include "utils.h"

#define LOG_FILE "/var/log/mosquitto/mqtt-pam.log"
#define MAX_LOG_LEN 256

/**
 * Write log message into log file LOG_FILE
 * @param message log message
 */
void write_log(const char *message)
{
    char date[32];
    char log[MAX_LOG_LEN];
    struct tm *sTm;
    FILE *fp;
    
    // Get current date
    time_t now = time(0);
    sTm = gmtime(&now);
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", sTm);

    // Save log
    snprintf(log, MAX_LOG_LEN-1, "%s: %s", date, message);

    // Open log file and write data
    fp = fopen(LOG_FILE, "w");
    //fwrite("%s\n", MAX_LOG_LEN, 1, fp);
    fprintf(fp, "%s\n", log);
}

/**
 * Log function callback
 * @param mosq mosquitto MQTT instance which call 
 * @param obj user data
 * @param level info log level
 * @param str log message
 */
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
    //write_log(str);
    printf("%s\n", str);
}

/**
 * Connect mosquitto instance to broker machine
 * @param mosq mosquitto MQTT instance
 * @param broker_host broker bind IP address
 * @param broker_port broker MQTT listening port
 * @return success connecting to broker MQTT
 */
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

/**
 * Stop mosquitto MQTT instance
 * @param mosq mosquitto MQTT instance to stop
 */
void stop_mosq(struct mosquitto *mosq)
{
	printf("Exiting...\n");
	if (mosquitto_disconnect(mosq) != MOSQ_ERR_SUCCESS)
	{
		fprintf(stderr, "Unable to stop server\n");
	}
}

#endif
