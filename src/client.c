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

// Global vars

#define PAYLOAD_SIZE 65
#define KEEPALIVE 60
#define TOPIC_SIZE 128
#define ID_SIZE 32
#define QoS 0
#define CLIENT_ID_TOPIC "client/pam/id"
#define CHALLENGE_TOPIC "pam/+/challenge"

static char *broker_host;
static int broker_port;
static char client_id[ID_SIZE];

// Mosquitto log callback
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

// Mosquitto message callback
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    int retval = 0;
    bool topic_match = false;
    static char send_hash_topic[TOPIC_SIZE];
    static char challenge[CHALLENGE_SIZE];
    static char challenge_hash[HASH_SIZE];
    struct Hash signed_hash;
    
    mosquitto_topic_matches_sub(CHALLENGE_TOPIC, message->topic, &topic_match);

    if (topic_match) // Server sends challenge
    {
        printf("Received challenge: %s\n", (char *)message->payload);
        set_buffer(challenge, CHALLENGE_SIZE, (char *)message->payload);
        
        if (strlen(challenge) > 0)
        {
            // Create hash topic
            set_topic(send_hash_topic, TOPIC_SIZE, client_id, "pam", "hash");

            // Create hash and sign it
            set_buffer(challenge_hash, HASH_SIZE, sha512(challenge));
            signed_hash = sign_hash(challenge_hash);
            
            if (strlen(signed_hash.digest) > 0)
            {
                // Send digest, pub key and signature
                mosquitto_publish(mosq, NULL, send_hash_topic, strlen(signed_hash.digest), signed_hash.digest, QoS, false);
                mosquitto_publish(mosq, NULL, send_hash_topic, strlen(signed_hash.pub_key), signed_hash.pub_key, QoS, false);
                mosquitto_publish(mosq, NULL, send_hash_topic, strlen(signed_hash.signature), signed_hash.signature, QoS, false);
                 
                if (retval != MOSQ_ERR_SUCCESS)
                {
                    fprintf(stderr, "%s(%s) = %d %s\n", "mosquitto_publish", send_hash_topic, retval, mosquitto_strerror(retval));
                }
            }
            else
            {
                fprintf(stderr, "Unable to sign hash\n");
            }       
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
}



//int hashes_match(const char *broker_host, const int broker_port)
//{
//    //Comprobacion regex ip broker host
//
//    //Comprobacion regex broker_port
//
//    
//}

//PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//	if (argc != 3)
//	{
//		fprintf(stderr, "Usage: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT>\n");
//		return PAM_PERM_DENIED;
//	}
//
//    char *broker_host = argv[1];
//	int broker_port = atoi(argv[2]);
//    int retval;
//
//    if (hashes_match(broker_host, broker_port))
//    {
//        return PAM_SUCCESS;
//    }
//    else 
//    {
//        return PAM_PERM_DENIED;
//    }
//}

// Set mosquitto instance to callbacks
void set_callbacks(struct mosquitto *mosq, const char *host, const int port)
{
	mosquitto_message_callback_set(mosq, message_callback);
	mosquitto_log_callback_set(mosq, log_callback);
}

int client_start(struct mosquitto *broker)
{
    int retval = 0;
    static char get_challenge_topic[TOPIC_SIZE];
  
    // Create challenge topic
    set_topic(get_challenge_topic, TOPIC_SIZE, "pam", client_id, "challenge");

    // Subscribe to challenge topic
    retval = mosquitto_subscribe(broker, NULL, get_challenge_topic, QoS);
    if (retval == MOSQ_ERR_SUCCESS) 
    {
        retval = mosquitto_publish(broker, NULL, CLIENT_ID_TOPIC, strlen(client_id), client_id, QoS, false);
        if (retval != MOSQ_ERR_SUCCESS)
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

int connect_to_broker(struct mosquitto *broker, const char *broker_host, const int broker_port)
{
    int retval = 0;

    retval = mosquitto_connect(broker, broker_host, broker_port, KEEPALIVE);
    if (retval == MOSQ_ERR_SUCCESS)
    {
        set_callbacks(broker, broker_host, broker_port);
    }
    else
    {
        fprintf(stderr, "%s = %d %s\n", "mosquitto_connect", retval, mosquitto_strerror(retval));
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
