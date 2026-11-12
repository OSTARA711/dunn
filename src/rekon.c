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
 * Copy a value from os-release.
 *
 * Handles quoted and unquoted values without executing
 * or interpreting the file as a shell script.
 */

static void copy_os_value(
        char *destination,
        size_t destination_size,
        const char *value)
{
    size_t length = 0;
    char quote = '\0';


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
                value++;
            }
        }
        else
        {
            if (*value == '#' ||
                isspace((unsigned char)*value))
            {
                break;
            }
        }


        destination[length++] = *value++;
    }


    destination[length] = '\0';
}



/*
 * Read operating system information.
 *
 * /etc/os-release is preferred.
 * /usr/lib/os-release is used as a fallback.
 */

static int read_os_release(DunnSystemInfo *system)
{
    FILE *fp;

    char line[512];

    int found_name = 0;
    int found_version = 0;


    fp = fopen("/etc/os-release", "r");

    if (!fp)
        fp = fopen("/usr/lib/os-release", "r");

    if (!fp)
        return 0;


    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "NAME=", 5) == 0)
        {
            copy_os_value(
                    system->os_name,
                    sizeof(system->os_name),
                    line + 5);

            found_name = system->os_name[0] != '\0';
        }


        else if (strncmp(line, "VERSION_ID=", 11) == 0)
        {
            copy_os_value(
                    system->os_version,
                    sizeof(system->os_version),
                    line + 11);

            found_version = system->os_version[0] != '\0';
        }


        else if (strncmp(line, "PRETTY_NAME=", 12) == 0 &&
                 !found_name)
        {
            copy_os_value(
                    system->os_name,
                    sizeof(system->os_name),
                    line + 12);

            found_name = system->os_name[0] != '\0';
        }
    }


    fclose(fp);

    return found_name || found_version;
}



/*
 * System reconnaissance.
 *
 * Collects distribution and kernel information.
 * Does not require elevated privileges.
 */

DunnDiscoveryResult dunn_rekon_system(
        DunnSystemInfo *system)
{
    struct utsname information;

    int os_found;


    if (!system)
        return DUNN_DISCOVERY_FAILED;


    memset(system, 0, sizeof(*system));


    /*
     * Operating system information.
     */

    os_found = read_os_release(system);


    /*
     * Kernel and architecture information.
     */

    if (uname(&information) != 0)
        {
       	return DUNN_DISCOVERY_FAILED;
       	}


        snprintf(system->kernel_name,
             sizeof(system->kernel_name),
             "%.*s",
             (int)sizeof(system->kernel_name) - 1,
             information.sysname);


        snprintf(system->kernel_release,
             sizeof(system->kernel_release),
             "%.*s",
             (int)sizeof(system->kernel_release) - 1,
             information.release);


        snprintf(system->architecture,
             sizeof(system->architecture),
             "%.*s",
             (int)sizeof(system->architecture) - 1,
             information.machine);


    /*
     * A missing os-release file does not prevent
     * successful kernel reconnaissance.
     */

    if (!os_found ||
        system->os_name[0] == '\0' ||
        system->os_version[0] == '\0')
    {
        return DUNN_DISCOVERY_PARTIAL;
    }


    return DUNN_DISCOVERY_OK;
}
