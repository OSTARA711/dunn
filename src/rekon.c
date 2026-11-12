/*
 * DUNN - Firewall Security Monitor
 *
 * src/rekon.c
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#include "dunn.h"


/*
 * Copy and decode a value from os-release.
 *
 * The file is read as data, never executed as a shell script.
 *
 * Supports:
 * - Unquoted values.
 * - Single-quoted values.
 * - Double-quoted values.
 * - Escaped characters in double-quoted values.
 */

static void copy_os_value(
        char *destination,
        size_t destination_size,
        const char *value)
{
    size_t length = 0;
    char quote = '\0';


    if (!destination || destination_size == 0 || !value)
        return;


    destination[0] = '\0';


    while (isspace((unsigned char)*value))
        value++;


    if (*value == '"' || *value == '\'')
    {
        quote = *value;
        value++;
    }


    while (*value && length < destination_size - 1)
    {
        if (quote)
        {
            if (*value == quote)
                break;


            if (quote == '"' && *value == '\\' && value[1])
            {
                char escaped = value[1];

                if (escaped == '\\' ||
                    escaped == '"' ||
                    escaped == '$' ||
                    escaped == '`')
                {
                    destination[length++] = escaped;
                    value += 2;
                    continue;
                }
            }
        }
        else
        {
            if (isspace((unsigned char)*value) ||
                *value == '#')
            {
                break;
            }
        }


        destination[length++] = *value++;
    }


    destination[length] = '\0';
}


/*
 * Read one os-release file.
 *
 * Returns:
 *   1  Information was found.
 *   0  No recognised information was found.
 *  -1  File could not be opened or read.
 */

static int read_os_release_file(
        const char *path,
        char *pretty_name,
        size_t pretty_name_size,
        char *name,
        size_t name_size,
        char *version,
        size_t version_size)
{
    FILE *fp;

    char line[512];
    char *separator;

    int found = 0;


    fp = fopen(path, "r");

    if (!fp)
        return -1;


    while (fgets(line, sizeof(line), fp))
    {
        /*
         * Ignore comments and empty lines.
         */

        if (line[0] == '#' || line[0] == '\n')
            continue;


        separator = strchr(line, '=');

        if (!separator)
            continue;


        *separator = '\0';

        const char *value = separator + 1;


        if (strcmp(line, "PRETTY_NAME") == 0)
        {
            copy_os_value(
                    pretty_name,
                    pretty_name_size,
                    value);

            found = pretty_name[0] != '\0' || found;
        }


        else if (strcmp(line, "NAME") == 0)
        {
            copy_os_value(
                    name,
                    name_size,
                    value);

            found = name[0] != '\0' || found;
        }


        else if (strcmp(line, "VERSION_ID") == 0)
        {
            copy_os_value(
                    version,
                    version_size,
                    value);

            found = version[0] != '\0' || found;
        }
    }


    int read_error = ferror(fp);

    fclose(fp);


    if (read_error)
        return -1;


    return found;
}


/*
 * Read operating system information.
 *
 * /etc/os-release is preferred.
 * /usr/lib/os-release is used as a fallback.
 *
 * PRETTY_NAME is preferred for the displayed OS name.
 */

static int read_os_release(DunnSystemInfo *system)
{
    char pretty_name[128] = "";
    char name[128] = "";
    char version[64] = "";

    int result;


    result = read_os_release_file(
            "/etc/os-release",
            pretty_name,
            sizeof(pretty_name),
            name,
            sizeof(name),
            version,
            sizeof(version));


    if (result < 0)
    {
        result = read_os_release_file(
                "/usr/lib/os-release",
                pretty_name,
                sizeof(pretty_name),
                name,
                sizeof(name),
                version,
                sizeof(version));
    }


    if (result <= 0)
        return result;


    /*
     * Prefer the complete distribution name.
     * Fall back to NAME if PRETTY_NAME is unavailable.
     */

    if (pretty_name[0] != '\0')
    {
        snprintf(
                system->os_name,
                sizeof(system->os_name),
                "%s",
                pretty_name);
    }
    else
    {
        snprintf(
                system->os_name,
                sizeof(system->os_name),
                "%s",
                name);
    }


    snprintf(
            system->os_version,
            sizeof(system->os_version),
            "%s",
            version);


    return 1;
}


/*
 * System reconnaissance.
 *
 * Collects distribution and kernel information.
 *
 * Does not:
 * - Require root privileges.
 * - Execute external commands.
 * - Install or modify software.
 * - Change system configuration.
 */

DunnDiscoveryResult dunn_rekon_system(
        DunnSystemInfo *system)
{
    struct utsname information;

    int os_result;


    if (!system)
        return DUNN_DISCOVERY_FAILED;


    memset(system, 0, sizeof(*system));


    /*
     * Operating system information.
     */

    os_result = read_os_release(system);


    /*
     * Kernel and architecture information.
     */

    if (uname(&information) != 0)
    	{
        return DUNN_DISCOVERY_FAILED;
	}

    snprintf(
            system->kernel_name,
            sizeof(system->kernel_name),
            "%.*s",
            (int)sizeof(system->kernel_name) - 1,
            information.sysname);


    snprintf(
            system->kernel_release,
            sizeof(system->kernel_release),
            "%.*s",
            (int)sizeof(system->kernel_release) - 1,
            information.release);


    snprintf(
            system->architecture,
            sizeof(system->architecture),
            "%.*s",
            (int)sizeof(system->architecture) - 1,
            information.machine);


    /*
     * Kernel reconnaissance succeeded.
     *
     * Missing or incomplete distribution information
     * produces a partial result, not a total failure.
     */

    if (os_result != 1 ||
        system->os_name[0] == '\0' ||
        system->os_version[0] == '\0')
    {
        return DUNN_DISCOVERY_PARTIAL;
    }


    return DUNN_DISCOVERY_OK;
}
