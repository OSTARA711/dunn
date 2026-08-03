/*
 * DUNN - Firewall Security Monitor
 *
 * src/ufw.c
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "dunn.h"


int dunn_get_ufw_status(DunnFirewallStatus *status)
{
    FILE *fp;

    char line[256];


    fp = popen("sudo ufw status verbose", "r");

    if (!fp)
        return -1;


    while (fgets(line, sizeof(line), fp))
    {

        if (strstr(line, "Status: active"))
        {
            status->active = 1;
        }


        if (strstr(line, "Logging:"))
        {
            sscanf(line,
                   "Logging: %31[^\n]",
                   status->logging);
        }


        if (strstr(line, "Default:"))
        {
            sscanf(line,
                   "Default: %31[^,], %31[^,], %31[^\n]",
                   status->incoming_policy,
                   status->outgoing_policy,
                   status->routed_policy);
        }
    }


    pclose(fp);

    return 0;
}



int dunn_get_ufw_rules(
        DunnFirewallRule *rules,
        size_t max_rules,
        size_t *count)
{
    FILE *fp;

    char line[256];


    *count = 0;


    fp = popen("sudo ufw status numbered", "r");

    if (!fp)
        return -1;


    while (fgets(line, sizeof(line), fp))
    {

        if (*count >= max_rules)
            break;


        if (line[0] == '[')
        {
            DunnFirewallRule *rule =
                &rules[*count];


            memset(rule, 0, sizeof(DunnFirewallRule));


            sscanf(line,
                   "[ %d] %63s %31s %15s %63[^\n]",
                   &rule->id,
                   rule->destination,
                   rule->action,
                   rule->direction,
                   rule->source);


            (*count)++;
        }
    }


    pclose(fp);

    return 0;
}



int dunn_get_listening_ports(
        DunnListeningPort *ports,
        size_t max_ports,
        size_t *count)
{
    /*
     * Placeholder for first commit.
     *
     * Next step:
     * parse ss -tulpen
     * or directly inspect /proc/net files
     */


    (void)ports;
    (void)max_ports;


    *count = 0;

    return 0;
}
