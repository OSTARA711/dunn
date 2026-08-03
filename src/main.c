/*
 * DUNN - Firewall Security Monitor
 *
 * src/main.c
 */

#include <stdio.h>
#include <string.h>

#include "dunn.h"


int main(void)
{
    DunnSnapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));


    if (dunn_get_ufw_status(&snapshot.status) != 0)
    {
        fprintf(stderr,
                "DUNN: unable to read firewall status\n");

        return 1;
    }


    if (dunn_get_ufw_rules(
            snapshot.rules,
            DUNN_MAX_RULES,
            &snapshot.rule_count) != 0)
    {
        fprintf(stderr,
                "DUNN: unable to read firewall rules\n");

        return 1;
    }


    if (dunn_get_listening_ports(
            snapshot.ports,
            DUNN_MAX_PORTS,
            &snapshot.port_count) != 0)
    {
        fprintf(stderr,
                "DUNN: unable to read listening ports\n");

        return 1;
    }


    dunn_display_snapshot(&snapshot);


    return 0;
}
