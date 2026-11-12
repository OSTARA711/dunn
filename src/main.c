/*
 * DUNN - Firewall Security Monitor
 *
 * src/main.c
 */

#include <string.h>

#include "dunn.h"


/*
 * Determine the aggregate backend.
 *
 * Zero detected backends:
 *     DUNN_BACKEND_NONE
 *
 * One detected backend:
 *     That backend
 *
 * Multiple detected backends:
 *     DUNN_BACKEND_UNKNOWN
 *
 * Multiple backends may coexist. In particular,
 * UFW may manage rules through nftables.
 */

static DunnFirewallBackend determine_aggregate_backend(
        const DunnSnapshot *snapshot)
{
    DunnFirewallBackend detected = DUNN_BACKEND_NONE;
    size_t installed_count = 0;

    for (size_t i = 0; i < snapshot->backend_count; i++)
    {
        const DunnFirewallBackendInfo *backend =
            &snapshot->backends[i];

        if (backend->installation != DUNN_INSTALLATION_INSTALLED)
            continue;

        detected = backend->backend;
        installed_count++;
    }

    if (installed_count == 0)
        return DUNN_BACKEND_NONE;

    if (installed_count == 1)
        return detected;

    return DUNN_BACKEND_UNKNOWN;
}


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
     * Firewall backend reconnaissance.
     *
     * Inspect all supported backends independently.
     * This operation is read-only.
     */

    snapshot.backend_result =
        dunn_rekon_firewall_backends(
            snapshot.backends,
            DUNN_MAX_BACKENDS,
            &snapshot.backend_count);


    /*
     * Determine the aggregate backend.
     */

    snapshot.aggregate_backend =
        determine_aggregate_backend(&snapshot);


    /*
     * UFW status.
     *
     * UFW-specific inspection is performed only when
     * its executable has been detected.
     */

    int ufw_available = 0;

    for (size_t i = 0; i < snapshot.backend_count; i++)
    {
        if (snapshot.backends[i].backend == DUNN_BACKEND_UFW &&
            snapshot.backends[i].installation == DUNN_INSTALLATION_INSTALLED)
        {
            ufw_available = 1;
            break;
        }
    }


    if (ufw_available)
    {
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
         * UFW firewall rules.
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
    }
    else
    {
        snapshot.firewall_result =
            DUNN_DISCOVERY_UNAVAILABLE;

        snapshot.rules_result =
            DUNN_DISCOVERY_UNAVAILABLE;
    }


    /*
     * Listening ports.
     *
     * This operation is independent of firewall
     * backend availability.
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
