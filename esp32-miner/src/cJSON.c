#include "cJSON.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cJSON_Delete(cJSON *item);

static cJSON *cjson_new(int type) {
    cJSON *item = (cJSON *)calloc(1, sizeof(cJSON));
    if (item) {
        item->type = type;
    }
    return item;
}

static void cjson_add_child(cJSON *parent, cJSON *child) {
    if (!parent->child) {
        parent->child = child;
        return;
    }
    cJSON *last = parent->child;
    while (last->next) {
        last = last->next;
    }
    last->next = child;
    child->prev = last;
}

static const char *skip_ws(const char *s) {
    while (s && *s && isspace((unsigned char)*s)) {
        s++;
    }
    return s;
}

static char *dup_range(const char *start, size_t len) {
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static const char *parse_string_raw(const char *s, char **out) {
    if (*s != '"') return NULL;
    s++;
    const char *start = s;
    size_t len = 0;
    char *buf = NULL;
    size_t cap = 0;

    while (*s) {
        if (*s == '"') {
            if (!buf) {
                *out = dup_range(start, len);
            } else {
                buf[len] = '\0';
                *out = buf;
            }
            return s + 1;
        }
        if (*s == '\\') {
            s++;
            if (!*s) break;
            char c = *s;
            if (!buf) {
                cap = (strlen(start) + 1u) * 2u;
                buf = (char *)malloc(cap);
                if (!buf) return NULL;
                len = 0;
                const char *p = start;
                while (p < s - 1) {
                    if (*p == '\\') break;
                    buf[len++] = *p++;
                }
            }
            if (len + 2 >= cap) {
                cap *= 2u;
                char *nb = (char *)realloc(buf, cap);
                if (!nb) {
                    free(buf);
                    return NULL;
                }
                buf = nb;
            }
            switch (c) {
                case '"': buf[len++] = '"'; break;
                case '\\': buf[len++] = '\\'; break;
                case '/': buf[len++] = '/'; break;
                case 'b': buf[len++] = '\b'; break;
                case 'f': buf[len++] = '\f'; break;
                case 'n': buf[len++] = '\n'; break;
                case 'r': buf[len++] = '\r'; break;
                case 't': buf[len++] = '\t'; break;
                default: buf[len++] = c; break;
            }
            s++;
            continue;
        }
        if (buf) {
            if (len + 2 >= cap) {
                cap *= 2u;
                char *nb = (char *)realloc(buf, cap);
                if (!nb) {
                    free(buf);
                    return NULL;
                }
                buf = nb;
            }
            buf[len++] = *s++;
        } else {
            s++;
            len++;
        }
    }
    free(buf);
    return NULL;
}

static const char *parse_value(const char *s, cJSON **out);

static const char *parse_number_raw(const char *s, cJSON **out) {
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == s) return NULL;
    cJSON *item = cjson_new(cJSON_Number);
    if (!item) return NULL;
    item->valuedouble = v;
    item->valueint = (int)v;
    *out = item;
    return end;
}

static const char *parse_array_raw(const char *s, cJSON **out) {
    if (*s != '[') return NULL;
    cJSON *array = cjson_new(cJSON_Array);
    if (!array) return NULL;
    s = skip_ws(s + 1);
    if (*s == ']') {
        *out = array;
        return s + 1;
    }
    while (*s) {
        cJSON *child = NULL;
        s = parse_value(s, &child);
        if (!s) {
            cJSON_Delete(array);
            return NULL;
        }
        cjson_add_child(array, child);
        s = skip_ws(s);
        if (*s == ',') {
            s = skip_ws(s + 1);
            continue;
        }
        if (*s == ']') {
            *out = array;
            return s + 1;
        }
        break;
    }
    cJSON_Delete(array);
    return NULL;
}

static const char *parse_object_raw(const char *s, cJSON **out) {
    if (*s != '{') return NULL;
    cJSON *object = cjson_new(cJSON_Object);
    if (!object) return NULL;
    s = skip_ws(s + 1);
    if (*s == '}') {
        *out = object;
        return s + 1;
    }
    while (*s) {
        char *key = NULL;
        if (*s != '"') {
            cJSON_Delete(object);
            return NULL;
        }
        s = parse_string_raw(s, &key);
        if (!s) {
            cJSON_Delete(object);
            return NULL;
        }
        s = skip_ws(s);
        if (*s != ':') {
            free(key);
            cJSON_Delete(object);
            return NULL;
        }
        s = skip_ws(s + 1);
        cJSON *child = NULL;
        s = parse_value(s, &child);
        if (!s) {
            free(key);
            cJSON_Delete(object);
            return NULL;
        }
        child->string = key;
        cjson_add_child(object, child);
        s = skip_ws(s);
        if (*s == ',') {
            s = skip_ws(s + 1);
            continue;
        }
        if (*s == '}') {
            *out = object;
            return s + 1;
        }
        break;
    }
    cJSON_Delete(object);
    return NULL;
}

static const char *parse_true_raw(const char *s, cJSON **out) {
    if (strncmp(s, "true", 4) != 0) return NULL;
    cJSON *item = cjson_new(cJSON_True);
    if (!item) return NULL;
    item->valueint = 1;
    item->valuedouble = 1.0;
    *out = item;
    return s + 4;
}

static const char *parse_false_raw(const char *s, cJSON **out) {
    if (strncmp(s, "false", 5) != 0) return NULL;
    cJSON *item = cjson_new(cJSON_False);
    if (!item) return NULL;
    *out = item;
    return s + 5;
}

static const char *parse_null_raw(const char *s, cJSON **out) {
    if (strncmp(s, "null", 4) != 0) return NULL;
    cJSON *item = cjson_new(cJSON_NULL);
    if (!item) return NULL;
    *out = item;
    return s + 4;
}

static const char *parse_value(const char *s, cJSON **out) {
    s = skip_ws(s);
    if (!s || !*s) return NULL;
    if (*s == '{') return parse_object_raw(s, out);
    if (*s == '[') return parse_array_raw(s, out);
    if (*s == '"') {
        char *str = NULL;
        const char *end = parse_string_raw(s, &str);
        if (!end) return NULL;
        cJSON *item = cjson_new(cJSON_String);
        if (!item) {
            free(str);
            return NULL;
        }
        item->valuestring = str;
        *out = item;
        return end;
    }
    if (*s == 't') return parse_true_raw(s, out);
    if (*s == 'f') return parse_false_raw(s, out);
    if (*s == 'n') return parse_null_raw(s, out);
    return parse_number_raw(s, out);
}

cJSON *cJSON_Parse(const char *value) {
    if (!value) return NULL;
    cJSON *root = NULL;
    const char *end = parse_value(value, &root);
    if (!end) return NULL;
    return root;
}

void cJSON_Delete(cJSON *item) {
    while (item) {
        cJSON *next = item->next;
        if (item->child) cJSON_Delete(item->child);
        free(item->valuestring);
        free(item->string);
        free(item);
        item = next;
    }
}

cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string) {
    if (!object || !(object->type & cJSON_Object) || !string) return NULL;
    for (cJSON *child = object->child; child; child = child->next) {
        if (child->string && strcmp(child->string, string) == 0) {
            return child;
        }
    }
    return NULL;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index) {
    if (!array || !(array->type & cJSON_Array) || index < 0) return NULL;
    cJSON *child = array->child;
    while (child && index--) {
        child = child->next;
    }
    return child;
}

int cJSON_GetArraySize(const cJSON *array) {
    if (!array || !(array->type & cJSON_Array)) return 0;
    int count = 0;
    for (cJSON *child = array->child; child; child = child->next) {
        count++;
    }
    return count;
}

int cJSON_IsString(const cJSON *item) { return item && (item->type & cJSON_String); }
int cJSON_IsNumber(const cJSON *item) { return item && (item->type & cJSON_Number); }
int cJSON_IsArray(const cJSON *item) { return item && (item->type & cJSON_Array); }
int cJSON_IsObject(const cJSON *item) { return item && (item->type & cJSON_Object); }
int cJSON_IsTrue(const cJSON *item) { return item && (item->type & cJSON_True); }
int cJSON_IsNull(const cJSON *item) { return item && (item->type & cJSON_NULL); }

static size_t json_print_len(const cJSON *item) {
    if (!item) return 4;
    if (cJSON_IsString(item)) return strlen(item->valuestring ? item->valuestring : "") + 2;
    if (cJSON_IsNumber(item)) return 32;
    if (cJSON_IsTrue(item)) return 4;
    if (item->type & cJSON_False) return 5;
    if (cJSON_IsNull(item)) return 4;
    if (cJSON_IsArray(item) || cJSON_IsObject(item)) return 16;
    return 4;
}

char *cJSON_PrintUnformatted(const cJSON *item) {
    size_t len = json_print_len(item) + 1;
    char *out = (char *)malloc(len);
    if (!out) return NULL;
    if (!item) {
        strcpy(out, "null");
        return out;
    }
    if (cJSON_IsString(item)) {
        snprintf(out, len, "\"%s\"", item->valuestring ? item->valuestring : "");
    } else if (cJSON_IsNumber(item)) {
        snprintf(out, len, "%g", item->valuedouble);
    } else if (cJSON_IsTrue(item)) {
        strcpy(out, "true");
    } else if (item->type & cJSON_False) {
        strcpy(out, "false");
    } else if (cJSON_IsNull(item)) {
        strcpy(out, "null");
    } else if (cJSON_IsArray(item)) {
        strcpy(out, "[]");
    } else if (cJSON_IsObject(item)) {
        strcpy(out, "{}");
    } else {
        strcpy(out, "null");
    }
    return out;
}
