#include <stdio.h>
#include <mosquitto.h>


void on_connect1(struct mosquitto *mosq, void *obj, int result)
{
    int rc = MOSQ_ERR_SUCCESS;

    if(!result){
        mosquitto_subscribe(mosq, NULL, "/v1/topic1", 0);
    }else{
        fprintf(stderr, "%s\n", mosquitto_connack_string(result));
    }
}

void on_message1(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    struct mosquitto *mosq2 = (struct mosquitto *)obj;

    mosquitto_publish(mosq, NULL, "/v1/topic2", message->payloadlen, message->payload, message->qos, message->retain);
}

int main(int argc, char *argv[])
{
    struct mosquitto *mosq1, *mosq2;

    mosquitto_lib_init();

    mosq2 = mosquitto_new(NULL, true, NULL);
    mosq1 = mosquitto_new(NULL, true, mosq2);

    mosquitto_connect_callback_set(mosq1, on_connect1);
    mosquitto_message_callback_set(mosq1, on_message1);

    mosquitto_connect(mosq2, "mqtt.example.io", 1883, 60);
    mosquitto_connect(mosq1, "localhost", 1883, 60);

    mosquitto_loop_start(mosq2);
    mosquitto_loop_forever(mosq1, -1, 1);

    mosquitto_destroy(mosq1);
    mosquitto_destroy(mosq2);

    mosquitto_lib_cleanup();

    return 0;
}
