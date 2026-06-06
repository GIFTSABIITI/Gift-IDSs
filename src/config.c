#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define CONFIG_LINE_MAX 512

static char *trim_whitespace(char *text)
{
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';

    return text;
}

static int parse_positive_int(const char *value, int *out)
{
    char *end;
    long parsed;

    if (value == NULL || *value == '\0') {
        return 0;
    }

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 0 || parsed > INT_MAX) {
        return 0;
    }

    *out = (int)parsed;
    return 1;
}

static int parse_non_negative_int(const char *value, int *out)
{
    char *end;
    long parsed;

    if (value == NULL || *value == '\0') {
        return 0;
    }

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 0 || parsed > INT_MAX) {
        return 0;
    }

    *out = (int)parsed;
    return 1;
}

static int parse_bool_value(const char *value, int *out)
{
    if (value == NULL || *value == '\0') {
        return 0;
    }

    if (strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0) {
        *out = 1;
        return 1;
    }

    if (strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 ||
        strcmp(value, "0") == 0) {
        *out = 0;
        return 1;
    }

    return 0;
}

static void set_int_value(const char *key, const char *value, int *field, int line_number)
{
    int parsed;

    if (!parse_positive_int(value, &parsed)) {
        fprintf(stderr,
                "Warning: config line %d has invalid value for '%s'; keeping default %d\n",
                line_number,
                key,
                *field);
        return;
    }

    *field = parsed;
}

static void set_non_negative_int_value(const char *key, const char *value, int *field, int line_number)
{
    int parsed;

    if (!parse_non_negative_int(value, &parsed)) {
        fprintf(stderr,
                "Warning: config line %d has invalid value for '%s'; keeping default %d\n",
                line_number,
                key,
                *field);
        return;
    }

    *field = parsed;
}

static void set_bool_value(const char *key, const char *value, int *field, int line_number)
{
    int parsed;

    /*
     * Rule toggles are intentionally strict. A typo such as "treu" should not
     * silently turn a learning rule on or off; keeping the current value makes
     * config mistakes visible while preserving a safe default.
     */
    if (!parse_bool_value(value, &parsed)) {
        fprintf(stderr,
                "Warning: config line %d has invalid boolean for '%s'; keeping default %s\n",
                line_number,
                key,
                *field ? "true" : "false");
        return;
    }

    *field = parsed;
}

static void set_path_value(const char *key, const char *value, char *field, size_t field_size, int line_number)
{
    if (value == NULL || *value == '\0') {
        fprintf(stderr,
                "Warning: config line %d has empty value for '%s'; keeping default '%s'\n",
                line_number,
                key,
                field);
        return;
    }

    if (strlen(value) >= field_size) {
        fprintf(stderr,
                "Warning: config line %d value for '%s' is too long; keeping default '%s'\n",
                line_number,
                key,
                field);
        return;
    }

    snprintf(field, field_size, "%s", value);
}

void config_set_defaults(GiftIDSConfig *config)
{
    if (config == NULL) {
        return;
    }

    config->port_scan_threshold = 10;
    config->port_scan_window_seconds = 10;

    config->syn_flood_threshold = 30;
    config->syn_flood_window_seconds = 10;

    config->icmp_flood_threshold = 20;
    config->icmp_flood_window_seconds = 10;

    config->alert_cooldown_seconds = 10;

    config->enable_suspicious_port_rule = 1;
    config->enable_tcp_syn_watch_rule = 1;
    config->enable_icmp_echo_rule = 1;

    config->enable_port_scan_detection = 1;
    config->enable_syn_flood_detection = 1;
    config->enable_icmp_flood_detection = 1;

    snprintf(config->packet_log_file, sizeof(config->packet_log_file), "%s", GIFTIDS_DEFAULT_PACKET_LOG_FILE);
    snprintf(config->alert_log_file, sizeof(config->alert_log_file), "%s", GIFTIDS_DEFAULT_ALERT_LOG_FILE);
}

int config_load(const char *path, GiftIDSConfig *config)
{
    FILE *file;
    char line[CONFIG_LINE_MAX];
    int line_number = 0;

    if (config == NULL) {
        return -1;
    }

    if (path == NULL || *path == '\0') {
        path = GIFTIDS_CONFIG_PATH;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr,
                "Warning: config file '%s' could not be opened; using defaults (%s)\n",
                path,
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *key;
        char *value;
        char *separator;

        line_number++;
        key = trim_whitespace(line);

        if (*key == '\0' || *key == '#') {
            continue;
        }

        separator = strchr(key, '=');
        if (separator == NULL) {
            fprintf(stderr,
                    "Warning: config line %d is malformed; expected key=value\n",
                    line_number);
            continue;
        }

        *separator = '\0';
        value = trim_whitespace(separator + 1);
        key = trim_whitespace(key);

        if (*key == '\0') {
            fprintf(stderr,
                    "Warning: config line %d is malformed; empty key ignored\n",
                    line_number);
            continue;
        }

        if (strcmp(key, "port_scan_threshold") == 0) {
            set_int_value(key, value, &config->port_scan_threshold, line_number);
        } else if (strcmp(key, "port_scan_window_seconds") == 0) {
            set_int_value(key, value, &config->port_scan_window_seconds, line_number);
        } else if (strcmp(key, "syn_flood_threshold") == 0) {
            set_int_value(key, value, &config->syn_flood_threshold, line_number);
        } else if (strcmp(key, "syn_flood_window_seconds") == 0) {
            set_int_value(key, value, &config->syn_flood_window_seconds, line_number);
        } else if (strcmp(key, "icmp_flood_threshold") == 0) {
            set_int_value(key, value, &config->icmp_flood_threshold, line_number);
        } else if (strcmp(key, "icmp_flood_window_seconds") == 0) {
            set_int_value(key, value, &config->icmp_flood_window_seconds, line_number);
        } else if (strcmp(key, "alert_cooldown_seconds") == 0) {
            set_non_negative_int_value(key, value, &config->alert_cooldown_seconds, line_number);
        } else if (strcmp(key, "enable_suspicious_port_rule") == 0) {
            set_bool_value(key, value, &config->enable_suspicious_port_rule, line_number);
        } else if (strcmp(key, "enable_tcp_syn_watch_rule") == 0) {
            set_bool_value(key, value, &config->enable_tcp_syn_watch_rule, line_number);
        } else if (strcmp(key, "enable_icmp_echo_rule") == 0) {
            set_bool_value(key, value, &config->enable_icmp_echo_rule, line_number);
        } else if (strcmp(key, "enable_port_scan_detection") == 0) {
            set_bool_value(key, value, &config->enable_port_scan_detection, line_number);
        } else if (strcmp(key, "enable_syn_flood_detection") == 0) {
            set_bool_value(key, value, &config->enable_syn_flood_detection, line_number);
        } else if (strcmp(key, "enable_icmp_flood_detection") == 0) {
            set_bool_value(key, value, &config->enable_icmp_flood_detection, line_number);
        } else if (strcmp(key, "packet_log_file") == 0) {
            set_path_value(key, value, config->packet_log_file, sizeof(config->packet_log_file), line_number);
        } else if (strcmp(key, "alert_log_file") == 0) {
            set_path_value(key, value, config->alert_log_file, sizeof(config->alert_log_file), line_number);
        } else {
            fprintf(stderr,
                    "Warning: config line %d has unknown key '%s'; ignoring it\n",
                    line_number,
                    key);
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "Warning: error while reading config file '%s'\n", path);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}
