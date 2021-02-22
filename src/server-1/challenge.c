#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>
#include <stdlib.h>

/*
Use: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <CHALLENGE>
*/
// Global vars

//#define mqtt_host "172.16.1.100"
//#define mqtt_port 1883
#define KEEPALIVE 60
#define PAYLOAD_SIZE 65
#define COMMAND_SIZE 100
#define QoS 1
#define SHA256_SCRIPT_PATH "../sha256.sh"
#define HASH_PATH "./hash.txt"

//Function error handling
void mosquitto_error_handler(int *retval) {
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

// Main
int main(int argc, char* argv[]) {
        if (argc != 4) {
                fprintf(stderr, "Usage: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <TOPIC>\n");
                return 1;
        }
        
        struct mosquitto *mosq = NULL;
        int retval = 0;
        char *mqtt_host = argv[1];
        int mqtt_port = atoi(argv[2]);
        char *topic = argv[3];

        char command[100];
        snprintf(command, COMMAND_SIZE, "bash %s | tail -1 | awk -F['='] '{print $2}' > %s", SHA256_SCRIPT_PATH, HASH_PATH);
        system(command);
        char payload[PAYLOAD_SIZE];
        FILE *fp;
        fp = fopen(HASH_PATH, "r");
        fscanf(fp, "%s", payload);
        printf("payload: %s\n", payload);
        printf("payload size: %ld\n", sizeof(payload));

        mosquitto_lib_init();

        mosq = mosquitto_new(NULL, true, 0);

        if (mosq) {
                retval = mosquitto_connect(mosq, mqtt_host, mqtt_port, KEEPALIVE);
                printf("mosquitto_connect(): ");
                mosquitto_error_handler(&retval);

                retval = mosquitto_publish(mosq, NULL, topic, sizeof(payload), payload, QoS, false);
                printf("mosquitto_publish(): ");
                mosquitto_error_handler(&retval);
        } else {
                fprintf(stderr, "Error: Out of memory.\n");
                return 1;
        }

        mosquitto_lib_cleanup();

        return 0;
}
