#ifndef MQTT_H_
#define MQTT_H_

#define KEEPALIVE 60
#define TOPIC_SIZE 128
#define ID_SIZE 32
#define QoS 0
#define CLIENT_ID_TOPIC "client/pam/id"
#define CHALLENGE_TOPIC "pam/+/challenge"
#define GET_EC_PARAMS_TOPIC "+/pam/ec_params"
#define ENABLE_LOGS 0

void set_callbacks(struct mosquitto *mosq, const char *host, const int port);
void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str);
int connect_to_broker(struct mosquitto *broker, const char *broker_host, const int broker_port);

#endif
