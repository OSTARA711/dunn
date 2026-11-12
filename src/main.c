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


    /*
     * System reconnaissance.
     *
     * This operation does not require root privileges.
     * A discovery failure must not prevent other
     * inspection operations from running.
     */

    snapshot.system_result =
        dunn_rekon_system(&snapshot.system);


    /*
     * Firewall status.
     */

    if (dunn_get_ufw_status(&snapshot.status) != 0)
    {
        snapshot.firewall_result =
            DUNN_DISCOVERY_FAILED;
    }
    else
    {
        snapshot.firewall_result =
            DUNN_DISCOVERY_OK;
    }


    /*
     * Firewall rules.
     */

    if (dunn_get_ufw_rules(
            snapshot.rules,
            DUNN_MAX_RULES,
            &snapshot.rule_count) != 0)
    {
        snapshot.rules_result =
            DUNN_DISCOVERY_FAILED;
    }
    else
    {
        snapshot.rules_result =
            DUNN_DISCOVERY_OK;
    }


    /*
     * Listening ports.
     */

    if (dunn_get_listening_ports(
            snapshot.ports,
            DUNN_MAX_PORTS,
            &snapshot.port_count) != 0)
    {
        snapshot.ports_result =
            DUNN_DISCOVERY_FAILED;
    }
    else
    {
        snapshot.ports_result =
            DUNN_DISCOVERY_OK;
    }


    /*
     * Display collected information.
     */

    dunn_display_snapshot(&snapshot);


    return 0;
}
