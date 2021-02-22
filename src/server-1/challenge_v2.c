#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <mosquitto.h>
#include <sys/types.h>
#include <regex.h>

// Global vars

#define KEEPALIVE 60
#define MAX_PAYLOAD_SIZE 455
#define QoS 0
#define RETAIN_MESSAGE false

//Function error handling
void mosquitto_error_handler(int *retval)
{
        switch (*retval) {
                case MOSQ_ERR_SUCCESS:
                        printf("MOSQ_ERR_SUCCESS\n");
                        break;
                case MOSQ_ERR_INVAL:
                        printf("MOSQ_ERR_INVAL\n");
                        break;
                case MOSQ_ERR_ERRNO:
                        printf("MOSQ_ERR_ERRNO\n");
                        break;
                default:
                        printf("Unknown MOSQ return value\n");
        }
}

// Connect to mosq
void connect(struct mosquitto *mosq, char *host, int port) 
{        
        int retval = 0;
        retval = mosquitto_connect(mosq, host, port, KEEPALIVE);
        printf("mosquitto_connect(): ");
        mosquitto_error_handler(&retval);  
}

// Publish payload message to mosq published topic
void publish_message(struct mosquitto *mosq, char *topic, void *payload) 
{
        int retval = 0;
        retval = mosquitto_publish(mosq, NULL, topic, sizeof(payload), payload, QoS, RETAIN_MESSAGE);
        printf("mosquitto_publish(): ");
        mosquitto_error_handler(&retval);
}

void print_regerror (int errcode, size_t length, regex_t *compiled)
{
  char buffer[length];
  (void) regerror (errcode, compiled, buffer, length);
  fprintf(stderr, "Regex match failed: %s\n", buffer);
}

// Main
int main(int argc, char* argv[]) {
        if (argc != 5) {
                fprintf(stderr, "Usage: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <TOPIC> <CHALLENGE>\n");
                return 1;
        }

        int retval = 0;
        char *mqtt_host = argv[1];
        int mqtt_port = atoi(argv[2]);
        char *topic = argv[3];
        char *challenge = argv[4];
        size_t sz = 32;
        char topic[sz];
        // Check parameters format

        regex_t regex;
        retval = regcomp(&regex, "[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", REG_EXTENDED);
        if (retval) {
                fprintf(stderr, "Could not compile regex\n");
                return 1;
        }
        retval = regexec(&regex, mqtt_host, 0, NULL, 0);
        if (retval == REG_NOMATCH) {
                size_t length = regerror(retval, &regex, NULL, 0);
                print_regerror(retval, length, &regex);  
                fprintf(stderr, "You must specify a valid IP address\n");
                return 1;
        }
        regfree(&regex);
        if (mqtt_port < 0 || mqtt_port > 65535) {
                fprintf(stderr, "You must specify a valid port number\n");
                return 1;
        } 

        if (sizeof(challenge) > MAX_PAYLOAD_SIZE) {
                fprintf(stderr, "Paylod too big to be sent\n");
                return 1;
        } else {

        }

        //Initialize mosquitto 
        mosquitto_lib_init();
        struct mosquitto *mosq = NULL;
        mosq = mosquitto_new(NULL, true, 0);

        if (mosq) {
                mosquitto_connect(mosq, mqtt_host, mqtt_port, KEEPALIVE);
                //connect(mosq, mqtt_host, mqtt_port);
                mosquitto_publish(mosq, NULL, topic, sizeof(challenge), challenge, 0, false);
                //publish_message(mosq, topic, challenge);
        } else {
                fprintf(stderr, "Error: Out of memory.\n");
                return 1;
        }

        mosquitto_lib_cleanup();

        return 0;
}
