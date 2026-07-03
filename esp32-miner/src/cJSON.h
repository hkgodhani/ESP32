#ifndef CJSON_H
#define CJSON_H

#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cJSON {
    struct cJSON *next;
    struct cJSON *prev;
    struct cJSON *child;
    int type;
    char *valuestring;
    double valuedouble;
    int valueint;
    char *string;
} cJSON;

#define cJSON_False 0x01
#define cJSON_True 0x02
#define cJSON_NULL 0x04
#define cJSON_Number 0x08
#define cJSON_String 0x10
#define cJSON_Array 0x20
#define cJSON_Object 0x40

cJSON *cJSON_Parse(const char *value);
void cJSON_Delete(cJSON *item);
cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string);
cJSON *cJSON_GetArrayItem(const cJSON *array, int index);
int cJSON_GetArraySize(const cJSON *array);
int cJSON_IsString(const cJSON *item);
int cJSON_IsNumber(const cJSON *item);
int cJSON_IsArray(const cJSON *item);
int cJSON_IsObject(const cJSON *item);
int cJSON_IsTrue(const cJSON *item);
int cJSON_IsNull(const cJSON *item);
char *cJSON_PrintUnformatted(const cJSON *item);

#define cJSON_free free

#ifdef __cplusplus
}
#endif

#endif
