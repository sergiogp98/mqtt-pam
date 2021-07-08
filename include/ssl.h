/**
 * Header files with functions related to TLS
 */

#ifndef SSL_H_
#define SSL_H_

#include <stdio.h>
#include <mosquitto.h>
#include <errno.h>

// Default SSL properties
#define TLS_VERSION NULL //"tlsv1.2"
#define SSL_VERIFY 1 //SSL_VERIFY_PEER
#define CIPHER NULL

/**
 * Establish TLS connection with mosquitto MQTT instance using CA cert file
 * @param mosq mosquitto MQTT instance
 * @param cafile path to CA cert file
 * @return success establishing TLS connection
 */
int set_tls_connection(struct mosquitto *mosq, char *cafile)
{
    int retval;

    retval = mosquitto_tls_set(mosq, cafile, NULL, NULL, NULL, NULL);
    if (retval == MOSQ_ERR_SUCCESS)
    {
        retval = mosquitto_tls_insecure_set(mosq, false);
        if (retval == MOSQ_ERR_SUCCESS)
        {
            retval = mosquitto_tls_opts_set(mosq, SSL_VERIFY, TLS_VERSION, CIPHER);
            if (retval != MOSQ_ERR_SUCCESS)
            {
                fprintf(stderr, "mosquitto_tls_opts_set failed, %s\n", mosquitto_strerror(retval));
            }
        }
        else
        {
            fprintf(stderr, "mosquitto_tls_insecure_set failed, %s\n", mosquitto_strerror(retval));
        }
    }
    else
    {
        fprintf(stderr, "mosquitto_tls_set failed, %s\n", mosquitto_strerror(retval));
    }

    return retval;
}

#endif