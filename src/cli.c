#include "cli.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_option_text(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0) {
        return;
    }

    if (src == NULL) {
        src = "";
    }

    snprintf(dst, dst_size, "%s", src);
}

static const char *program_name(const char *program)
{
    const char *slash;

    if (program == NULL || *program == '\0') {
        return "giftids";
    }

    slash = strrchr(program, '/');
    if (slash != NULL && slash[1] != '\0') {
        return slash + 1;
    }

    return program;
}

static int parse_positive_long(const char *value, long *out)
{
    char *end;
    long parsed;

    if (value == NULL || *value == '\0') {
        return 0;
    }

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 0 || parsed == LONG_MAX) {
        return 0;
    }

    *out = parsed;
    return 1;
}

static int option_has_inline_value(const char *arg, const char *name, const char **value)
{
    size_t name_len;

    name_len = strlen(name);
    if (strcmp(arg, name) == 0) {
        *value = NULL;
        return 1;
    }

    if (strncmp(arg, name, name_len) == 0 && arg[name_len] == '=') {
        *value = arg + name_len + 1;
        return 1;
    }

    return 0;
}

static int next_value(int argc, char **argv, int *index, const char *option_name, const char **value)
{
    if (*value != NULL) {
        if (**value == '\0') {
            fprintf(stderr, "Error: missing value after %s\n", option_name);
            return -1;
        }
        return 0;
    }

    if (*index + 1 >= argc || argv[*index + 1][0] == '-') {
        fprintf(stderr, "Error: missing value after %s\n", option_name);
        return -1;
    }

    (*index)++;
    *value = argv[*index];
    return 0;
}

static int set_string_option(char *field,
                             size_t field_size,
                             const char *value,
                             const char *option_name)
{
    if (strlen(value) >= field_size) {
        fprintf(stderr, "Error: value for %s is too long\n", option_name);
        return -1;
    }

    copy_option_text(field, field_size, value);
    return 0;
}

void cli_set_defaults(GiftIDSRuntimeOptions *options)
{
    if (options == NULL) {
        return;
    }

    memset(options, 0, sizeof(*options));
    copy_option_text(options->config_path, sizeof(options->config_path), GIFTIDS_CONFIG_PATH);

    options->show_stats = 0;
    options->verbose = 0;
    options->quiet = 0;
    options->packet_logging_enabled = 1;
    options->alert_logging_enabled = 1;
    options->max_packets = 0;
}

int cli_parse_args(int argc, char **argv, GiftIDSRuntimeOptions *options)
{
    int i;

    if (options == NULL) {
        return -1;
    }

    cli_set_defaults(options);

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (option_has_inline_value(arg, "--interface", &value)) {
            if (next_value(argc, argv, &i, "--interface", &value) != 0 ||
                set_string_option(options->interface_name, sizeof(options->interface_name), value, "--interface") != 0) {
                return -1;
            }
        } else if (option_has_inline_value(arg, "--config", &value)) {
            if (next_value(argc, argv, &i, "--config", &value) != 0 ||
                set_string_option(options->config_path, sizeof(options->config_path), value, "--config") != 0) {
                return -1;
            }
        } else if (option_has_inline_value(arg, "--packet-log", &value)) {
            if (next_value(argc, argv, &i, "--packet-log", &value) != 0 ||
                set_string_option(options->packet_log_override, sizeof(options->packet_log_override), value, "--packet-log") != 0) {
                return -1;
            }
        } else if (option_has_inline_value(arg, "--alert-log", &value)) {
            if (next_value(argc, argv, &i, "--alert-log", &value) != 0 ||
                set_string_option(options->alert_log_override, sizeof(options->alert_log_override), value, "--alert-log") != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--stats") == 0) {
            options->show_stats = 1;
        } else if (strcmp(arg, "--no-packet-log") == 0) {
            options->packet_logging_enabled = 0;
        } else if (strcmp(arg, "--no-alert-log") == 0) {
            options->alert_logging_enabled = 0;
        } else if (strcmp(arg, "--verbose") == 0) {
            options->verbose = 1;
        } else if (strcmp(arg, "--quiet") == 0) {
            options->quiet = 1;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            options->show_help = 1;
        } else if (strcmp(arg, "--version") == 0) {
            options->show_version = 1;
        } else if (strcmp(arg, "-i") == 0) {
            value = NULL;
            if (next_value(argc, argv, &i, "-i", &value) != 0 ||
                set_string_option(options->interface_name, sizeof(options->interface_name), value, "-i") != 0) {
                return -1;
            }
        } else if (strcmp(arg, "-c") == 0 || option_has_inline_value(arg, "--count", &value)) {
            if (next_value(argc, argv, &i, strcmp(arg, "-c") == 0 ? "-c" : "--count", &value) != 0) {
                return -1;
            }
            if (!parse_positive_long(value, &options->max_packets)) {
                fprintf(stderr, "Error: packet count must be a positive number\n");
                return -1;
            }
        } else if (arg[0] == '-') {
            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            return -1;
        } else {
            fprintf(stderr, "Error: unexpected argument '%s'\n", arg);
            return -1;
        }
    }

    if (!options->show_help && !options->show_version && options->verbose && options->quiet) {
        fprintf(stderr, "Error: --verbose and --quiet cannot be used together\n");
        return -1;
    }

    return 0;
}

void cli_apply_config_overrides(const GiftIDSRuntimeOptions *options, GiftIDSConfig *config)
{
    if (options == NULL || config == NULL) {
        return;
    }

    /*
     * Command-line overrides take priority because terminal tools are often
     * reused in labs: one config can hold defaults, while a single run can
     * redirect logs or select a different interface without editing files.
     */
    if (options->packet_log_override[0] != '\0') {
        copy_option_text(config->packet_log_file,
                         sizeof(config->packet_log_file),
                         options->packet_log_override);
    }

    if (options->alert_log_override[0] != '\0') {
        copy_option_text(config->alert_log_file,
                         sizeof(config->alert_log_file),
                         options->alert_log_override);
    }
}

void cli_print_help(const char *program)
{
    const char *name = program_name(program);

    printf("Gift IDS - Learning-focused intrusion detection system\n");
    printf("\n");
    printf("Usage:\n");
    printf("  %s --interface <name> [options]\n", name);
    printf("\n");
    printf("Options:\n");
    printf("  --interface <name>       Network interface to capture from\n");
    printf("  --config <path>          Config file path\n");
    printf("  --packet-log <path>      Override packet log path\n");
    printf("  --alert-log <path>       Override alert log path\n");
    printf("  --stats                  Show live statistics\n");
    printf("  --no-packet-log          Disable packet event logging\n");
    printf("  --no-alert-log           Disable alert logging\n");
    printf("  --verbose                Print detailed packet output\n");
    printf("  --quiet                  Print only alerts and important messages\n");
    printf("  --help                   Show this help message\n");
    printf("  --version                Show version information\n");
    printf("\n");
    printf("Examples:\n");
    printf("  sudo ./%s --interface wlan0\n", name);
    printf("  sudo ./%s --interface eth0 --stats\n", name);
    printf("  sudo ./%s --interface wlan0 --config config/giftids.conf --verbose\n", name);
    printf("  sudo ./%s --interface eth0 --packet-log logs/lab_packets.log --alert-log logs/lab_alerts.log\n", name);
}

void cli_print_version(void)
{
    printf("Gift IDS version %s\n", GIFTIDS_VERSION);
}
