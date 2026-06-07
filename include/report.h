#ifndef REPORT_H
#define REPORT_H

#include "cli.h"
#include "config.h"

int report_generate(const char *path,
                    const char *format,
                    const GiftIDSRuntimeOptions *options,
                    const GiftIDSConfig *config);
int report_generate_text(const char *path,
                         const GiftIDSRuntimeOptions *options,
                         const GiftIDSConfig *config);
int report_generate_json(const char *path,
                         const GiftIDSRuntimeOptions *options,
                         const GiftIDSConfig *config);

#endif
