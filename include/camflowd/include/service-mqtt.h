/*
*
* Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
*
* Copyright (C) 2016-2017 Harvard University
* Copyright (C) 2017-2018 University of Cambridge
* Copyright (C) 2018-2019 University of Bristol
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef __SERVICE_MQTT_H
#define __SERVICE_MQTT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <syslog.h>
#include <MQTTClient.h>

#include "service-config.h"

#define gettid() syscall(SYS_gettid)
#define TIMEOUT         10000L

static MQTTClient __service_client;

static inline void init_mqtt(void){
  int rc;
  uint32_t machine_id;
  rc = provenance_get_machine_id(&machine_id);
  if(rc<0){
    syslog(LOG_ERR, "Failed retrieving machine ID.");
    exit(rc);
  }
  snprintf(__service_config.provenance_topic, MAX_TOPIC_LENGTH, "%s%u", __service_config.provenance_topic_prefix, machine_id);
  snprintf(__service_config.client_id, MAX_MQTT_CLIENT_ID_LENGTH, "%u", machine_id); // should be no more than 23
  syslog(LOG_INFO, "Provenance topic: %s.", __service_config.provenance_topic);
  syslog(LOG_INFO, "Address: %s.", __service_config.address);
  MQTTClient_create(&__service_client,
    __service_config.address,
    __service_config.client_id,
    MQTTCLIENT_PERSISTENCE_NONE,
    NULL);
}

static inline void stop_mqtt(void){
  MQTTClient_disconnect(__service_client, 10000);
  MQTTClient_destroy(&__service_client);
}

static inline void mqtt_connect(bool cleansession){
  pid_t tid = gettid();
  MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
  int rc;
  conn_opts.keepAliveInterval = 20;
  if(cleansession){
    conn_opts.cleansession = 1;
  }else{
    conn_opts.cleansession = 0;
  }
  conn_opts.reliable = 1;
  conn_opts.username = __service_config.username;
  conn_opts.password = __service_config.password;

  syslog(LOG_INFO, "Connecting to MQTT... (%d)", tid);
  if ((rc = MQTTClient_connect(__service_client, &conn_opts)) != MQTTCLIENT_SUCCESS)
  {
      syslog(LOG_ERR, "camflowd: failed to connect, return code %d\n", rc);
      exit(-1);
  }
  syslog(LOG_INFO, "Connected (%d)", tid);
}

static pthread_mutex_t l_mqtt = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
/* publish payload on mqtt */
static inline void mqtt_publish(char* topic, char* payload, int qos, bool retained){
  pid_t tid = gettid();
  int rc;
  int retry=0; // give up after a while.
  MQTTClient_message pubmsg = MQTTClient_message_initializer;
  MQTTClient_deliveryToken token;

  if(payload==NULL){
    pubmsg.payload = NULL;
    pubmsg.payloadlen = 0;
  }else{
    pubmsg.payload = payload;
    pubmsg.payloadlen = strlen(payload);
  }

  pubmsg.qos = qos;

  if(retained){
    pubmsg.retained = 1;
  }else{
    pubmsg.retained = 0;
  }


  do{
    pthread_mutex_lock(&l_mqtt); // set to reliable only a message at a time

    if( !MQTTClient_isConnected(__service_client) ){
      mqtt_connect(false);
    }

    MQTTClient_publishMessage(__service_client, topic, &pubmsg, &token);
    rc = MQTTClient_waitForCompletion(__service_client, token, TIMEOUT);

    pthread_mutex_unlock(&l_mqtt);

    if(rc != MQTTCLIENT_SUCCESS){
      syslog(LOG_ERR, "MQTT disconnected error: %d (%d)", rc, tid);
      retry++;
    }
    if(retry > 10){
      syslog(LOG_ERR, "Failed connect retry (%d)", tid);
      break;
    }
  }while(rc != MQTTCLIENT_SUCCESS);
}

static inline void publish_json(char* topic, const char* json, bool retain){
  size_t len;
  char* buf;
  const size_t inlen = strlen(json);
  len = compress64encodeBound(inlen);
  buf = (char*)malloc(len);
  compress64encode(json, inlen, buf, len);
  mqtt_publish(topic, buf, __service_config.qos, retain);
  free(buf);
}

static inline void mqtt_print_json(char* json){
  publish_json(__service_config.provenance_topic, json, false);
}
#endif
