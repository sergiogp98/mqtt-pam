#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <openssl/sha.h>
#include "../lib/crypt.h"
#include "../lib/ecdsa.h"
#include "../lib/utils.h"
#include "../lib/mqtt.h"

// Global vars
static char *broker_host;
static int broker_port;
static char client_id[ID_SIZE];

// Mosquitto message callback
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    int retval = 0;
    bool topic_match = false;
    static char send_ec_params_topic[TOPIC_SIZE];
    static char challenge[CHALLENGE_SIZE];
    static char challenge_hash[HASH_SIZE];
    struct EC_PARAMS ec_params;
    ECDSA_SIG *signature; 
    EC_KEY *pub_key;

    mosquitto_topic_matches_sub(CHALLENGE_TOPIC, message->topic, &topic_match);

    if (topic_match) // Server sends challenge
    {
        printf("Received challenge: %s\n", (char *)message->payload);
        set_buffer(challenge, CHALLENGE_SIZE, (char *)message->payload);

        if (strlen(challenge) > 0)
        {
            // Create hash topic
            set_topic(send_ec_params_topic, TOPIC_SIZE, client_id, "pam", "ec_params");

            // Create hash and sign it
            set_buffer(challenge_hash, HASH_SIZE, sha512(challenge));
            //printf("hash: %s\n", challenge_hash);
            ec_params = sign_hash(challenge_hash, HASH_SIZE);
            
            // Send ec_param values to client
            mosquitto_publish(mosq, NULL, send_ec_params_topic, strlen(ec_params.pub_key), ec_params.pub_key, QoS, false);
            mosquitto_publish(mosq, NULL, send_ec_params_topic, strlen(ec_params.r), ec_params.r, QoS, false);
            mosquitto_publish(mosq, NULL, send_ec_params_topic, strlen(ec_params.s), ec_params.s, QoS, false);
        }
        else
        {
            fprintf(stderr, "Empty challenge\n");
        }
    }
    else
    {
        fprintf(stderr, "Unknow topic: %s", message->topic);
    }

    mosquitto_message_free((struct mosquitto_message **) message);
}

int client_start(struct mosquitto *mosq)
{
    int retval = 0;
    static char get_challenge_topic[TOPIC_SIZE];

    // Create challenge topic
    set_topic(get_challenge_topic, TOPIC_SIZE, "pam", client_id, "challenge");

    // Subscribe to challenge topic
    retval = mosquitto_subscribe(mosq, NULL, get_challenge_topic, QoS);
    if (retval == MOSQ_ERR_SUCCESS)
    {   
        retval = mosquitto_publish(mosq, NULL, CLIENT_ID_TOPIC, strlen(client_id), client_id, QoS, false);
        if (retval == MOSQ_ERR_SUCCESS)
        {
            mosquitto_message_callback_set(mosq, message_callback);
        }
        else
        {
            fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_publish", CLIENT_ID_TOPIC, retval, mosquitto_strerror(retval));
        }
    }
    else
    {
        fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", get_challenge_topic, retval, mosquitto_strerror(retval));
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

    struct mosquitto *client = NULL;
    int retval = 0;

    // Check host and port

    broker_host = argv[1];
    broker_port = atoi(argv[2]);

    mosquitto_lib_init();

    set_id(client_id, ID_SIZE, "client");
    client = mosquitto_new(client_id, true, NULL);
    if (client)
    {
        if (connect_to_broker(client, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
        {
            if (client_start(client) == MOSQ_ERR_SUCCESS)
            {
                printf("Successfully start client\n");
            }
            else
            {
                fprintf(stderr, "Unable to start client\n");
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Unable to connect to broker\n");
            return 1;
        }
    }
    else
    {
        perror("mosquitto_new");
    }

    mosquitto_loop_start(client);
    mosquitto_loop_forever(client, -1, 1);
    mosquitto_destroy(client);

    mosquitto_lib_cleanup();

    return 0;
}
