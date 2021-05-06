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
#include <security/pam_appl.h>
#include <security/pam_modules.h>

// Global vars
static char *broker_host;
static int broker_port;
const char *client_id = "21fb034c-c837-407a-a585-cee50ed9a74c";

// Mosquitto message callback
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    int retval = 0;
    bool topic_match = false;
    static char send_r_topic[TOPIC_SIZE];
    static char send_s_topic[TOPIC_SIZE];
    static char challenge[CHALLENGE_SIZE];
    static char challenge_hash[HASH_SIZE];
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
            ec_sign = sign_hash(challenge_hash, HASH_SIZE);

            // Create ec_sign values topics
            set_topic(send_r_topic, TOPIC_SIZE, client_id, "pam", "r");
            set_topic(send_s_topic, TOPIC_SIZE, client_id, "pam", "s");

            // Send ec_param values to client
            mosquitto_publish(mosq, NULL, send_r_topic, strlen(ec_sign.r), ec_sign.r, QoS, false);
            mosquitto_publish(mosq, NULL, send_s_topic, strlen(ec_sign.s), ec_sign.s, QoS, false);
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

void set_callbacks(struct mosquitto *mosq)
{
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
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
        printf("Listening to %s topic...\n", get_challenge_topic);
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

    // Set client-1 with uuid pem file in .anubis
    //strcpy(client_id, create_uuid());

    //set_id(client_id, ID_SIZE, "client");
    client = mosquitto_new(client_id, true, NULL);
    if (client)
    {
        set_callbacks(client);
        if (connect_to_broker(client, broker_host, broker_port) == MOSQ_ERR_SUCCESS)
        {
            if (client_start(client) != MOSQ_ERR_SUCCESS)
            {
               fprintf(stderr, "Unable to start client\n");
               retval = 1;
            }
        }
        else
        {
            fprintf(stderr, "Unable to connect to broker\n");
            retval =  1;
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

    return retval;
}