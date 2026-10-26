#pragma once

#include <stdint.h>
#include "../../httpserver/new_http.h"

void HAL_BLEMeshBK7231N_OnAdvertisement(const void *info);
void HAL_BLEMeshBK7231N_RegisterCommands(void);
void HAL_BLEMeshBK7231N_OnMqttCommand(const char *command, const char *args);
void HAL_BLEMeshBK7231N_OnSystemReady(void);
int HAL_BLEMeshBK7231N_WebConfig(http_request_t *request);
