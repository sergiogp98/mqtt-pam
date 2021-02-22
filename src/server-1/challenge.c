#include <stdio.h>
#include <errno.h>
#include <mosquitto.h>

/*
Use: ./challenge <BROKER_MQTT_IP_ADDRESS> <BROKER_MQTT_PORT> <CHALLENGE>
*/
// Global vars

#define mqtt_host "172.16.1.100"
#define mqtt_port 1883
#define keepalive 60
#define PAYLOAD_SIZE 455

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

// Connect to broker

// Send challenge to broker
//libmosq_EXPORT send_challenge_to_broker(long char *challenge, struct mosquitto *mosq, const char *host, int port, int keepalive) {
//        libmosq_EXPORT retval;
//        retval = mosquitto_connect(mosq, host, port, keepalive);
//        if (retval == MOSQ_ERR_SUCCESS) {
//                //Publish message
//		retval = mosquitto_publish(mosq, NULL, 
//        } else if (retval == MOSQ_ERR_INVAL) {
//                // Input parameter invalid
//                fprintf(stderr, "Invalid parameter in mosquitto_connect()");
//                exit(1);
//        } else {
//                //System call returned an error
//                fprintf(stderr, "System call returned an error");
//                exit(1);
//	}
//}
// Main
int main(int argc, char* argv[]) {
        struct mosquitto *mosq = NULL;
        int retval = 0;
        char payload[] = "Any payload...";
        char *topic = "server/ssh";

        mosquitto_lib_init();

        mosq = mosquitto_new(NULL, true, 0);

        if (mosq) {
                retval = mosquitto_connect(mosq, mqtt_host, mqtt_port, keepalive);
                printf("mosquitto_connect(): ");
                mosquitto_error_handler(&retval);

                retval = mosquitto_publish(mosq, NULL, topic, sizeof(payload), payload, 0, false);
                printf("mosquitto_publish(): ");
                mosquitto_error_handler(&retval);
        } else {
                fprintf(stderr, "Error: Out of memory.\n");
                return 1;
        }

        mosquitto_lib_cleanup();

        return 0;
}
