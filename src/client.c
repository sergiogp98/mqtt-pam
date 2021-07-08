/**
 * Client side script which run the following steps:
 * - Subscribe to challenge topic
 * - Sign challenge hash topic with private key
 * - Send EC sign values (r and s) in hex to server 
 */

#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/crypt.h"
#include "../include/ecdsa.h"
#include "../include/utils.h"
#include "../include/mqtt.h"
#include "../include/uuid.h"
#include "../include/ssl.h"

// Global vars
static char uuid[UUID_STR_LEN];

/**
 * Callback function which run whenever a message is received from a subscribed topic
 * @param mosq mosquitto instance making the callback
 * @param obj user data provided in mosquitto_new
 * @param message the message data
 */
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    int retval = 0;
    bool topic_match = false;
    static char send_r_topic[TOPIC_SIZE];
    static char send_s_topic[TOPIC_SIZE];
    static char challenge[CHALLENGE_SIZE];
    static char challenge_hash[HASH_SIZE];
    static char pemfile[MAX_PATH_LEN];
    struct EC_SIGN ec_sign;

    mosquitto_topic_matches_sub(CHALLENGE_TOPIC, message->topic, &topic_match);

    if (topic_match) // Server sends challenge
    {
        printf("Received challenge: %s\n", (char *)message->payload);
        set_buffer(challenge, CHALLENGE_SIZE, (char *)message->payload);
        
        if (strlen(challenge) > 0)
        {
            // Create challenge hash
            set_buffer(challenge_hash, HASH_SIZE, sha512(challenge));

            // Sign challenge hash
            sprintf(pemfile, "%s/.anubis/%s.key", getenv("HOME"), uuid);
            ec_sign = sign_hash(challenge_hash, HASH_SIZE, pemfile);

            // Create ec_sign values topics
            set_topic(send_r_topic, TOPIC_SIZE, uuid, "pam", "r");
            set_topic(send_s_topic, TOPIC_SIZE, uuid, "pam", "s");

            // Send ec_param values to client
            mosquitto_publish(mosq, NULL, send_r_topic, strlen(ec_sign.r), ec_sign.r, QoS, false);
            mosquitto_publish(mosq, NULL, send_s_topic, strlen(ec_sign.s), ec_sign.s, QoS, false);

            // Stop client
            stop_mosq(mosq);
        }
        else
        {
            fprintf(stderr, "Empty challenge\n");
            exit(1);
        }
    }
    else
    {
        fprintf(stderr, "Unknow topic: %s", message->topic);
        exit(1);
    }
}

/**
 * Link which function to use when using a specific callback
 * @param mosq mosquitto instance making the callback
 */
void set_callbacks(struct mosquitto *mosq)
{
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
}

/**
 * Start client function
 * @param mosq mosquitto instance
 * @return status of subscribing to challenge topic
 */
int client_start(struct mosquitto *mosq)
{
    int retval = 0;
    static char get_challenge_topic[TOPIC_SIZE];

    // Create challenge topic
    set_topic(get_challenge_topic, TOPIC_SIZE, "pam", uuid, "challenge");

    // Subscribe to challenge topic
    retval = mosquitto_subscribe(mosq, NULL, get_challenge_topic, QoS);
    if (retval == MOSQ_ERR_SUCCESS)
    {
        printf("Listening to %s topic...\n", get_challenge_topic);
    }
    else
    {
        fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_subscribe", get_challenge_topic, retval, mosquitto_strerror(retval));
    }

    return retval;
}

/**
 * Main function
 * @param argc number of arguments
 * @param argv array with arguments
 * @return Success starting client 
 */
int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        fprintf(stderr, "Usage: ./client <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <UUID> <CA_FILE>\n");
        return 1;
    }

    char broker_host[ID_SIZE];
    int broker_port = 0;
    struct mosquitto *client = NULL;
    int retval = 1;
    char cafile[MAX_PATH_LEN];

    // Save broker host and port
    set_buffer(broker_host, ID_SIZE, argv[1]);
    broker_port = atoi(argv[2]);

    // Save UUID
    set_buffer(uuid, UUID_STR_LEN, argv[3]);
    
    // Save ca file
    set_buffer(cafile, MAX_PATH_LEN, argv[4]);
    
    mosquitto_lib_init();

    client = mosquitto_new(uuid, true, NULL);
    if (client)
    {
        // Set TLS connection
        if (set_tls_connection(client, cafile) == MOSQ_ERR_SUCCESS)
        {
            set_callbacks(client);
            if (connect_to_broker(client, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
            {
                if (client_start(client) == MOSQ_ERR_SUCCESS)
                {
                    mosquitto_loop_start(client);
                    mosquitto_loop_forever(client, -1, 1);
                    retval = 0;
                }
                else
                {
                    fprintf(stderr, "Unable to start client\n");
                }
            }
            else
            {
                fprintf(stderr, "Unable to connect to broker\n");
            }
        }
        else
        {
            fprintf(stderr, "Unable to set TLS connection\n");
        }
        mosquitto_destroy(client);
    }
    else
    {
        perror("mosquitto_new");
    }

    mosquitto_lib_cleanup();

    return retval;
}