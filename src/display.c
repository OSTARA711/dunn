/*
 * DUNN - Firewall Security Monitor
 *
 * src/display.c
 */

#include <stdio.h>

#include "dunn.h"


#define GREEN        "\033[92m"
#define RED          "\033[91m"
#define YELLOW       "\033[93m"
#define BOLD         "\033[1m"
#define RESET        "\033[0m"


#define DISPLAY_WIDTH 44


static void separator(void)
{
    printf("--------------------------------------------\n");
}


static const char *discovery_result_name(
        DunnDiscoveryResult result)
{
    switch (result)
    {
        case DUNN_DISCOVERY_OK:
            return GREEN "OK" RESET;

        case DUNN_DISCOVERY_PARTIAL:
            return YELLOW "PARTIAL" RESET;

        case DUNN_DISCOVERY_UNAVAILABLE:
            return YELLOW "UNAVAILABLE" RESET;

        case DUNN_DISCOVERY_PERMISSION_DENIED:
            return RED "PERMISSION DENIED" RESET;

        case DUNN_DISCOVERY_FAILED:
            return RED "FAILED" RESET;

        case DUNN_DISCOVERY_NOT_RUN:
        default:
            return "NOT RUN";
    }
}


/*
 * DUNN terminal branding.
 *
 * The ASCII logo provides a larger visual identity
 * without depending on terminal-specific font controls.
 */

static void display_banner(void)
{
    printf("\n");

    printf(RESET);

    printf(GREEN);

    printf("                    DUNN\n");

    printf(RESET);

    printf("============================================\n");

    printf(GREEN);

    printf("         Firewall Security Monitor\n");

    printf(RESET);


    printf("============================================\n");
}


static void display_system(
        const DunnSnapshot *snapshot)
{
    printf("\nSYSTEM RECONNAISSANCE\n");
    separator();


    printf("Operating system : %s\n",
           snapshot->system.os_name[0]
               ? snapshot->system.os_name
               : "Unknown");


    printf("OS version       : %s\n",
           snapshot->system.os_version[0]
               ? snapshot->system.os_version
               : "Unknown");


    printf("Kernel           : %s\n",
           snapshot->system.kernel_name[0]
               ? snapshot->system.kernel_name
               : "Unknown");


    printf("Kernel release   : %s\n",
           snapshot->system.kernel_release[0]
               ? snapshot->system.kernel_release
               : "Unknown");


    printf("Architecture     : %s\n",
           snapshot->system.architecture[0]
               ? snapshot->system.architecture
               : "Unknown");


    printf("Discovery        : %s\n",
           discovery_result_name(snapshot->system_result));
}


static void display_firewall(
        const DunnSnapshot *snapshot)
{
    printf("\nFIREWALL STATUS\n");
    separator();


    switch (snapshot->status.state)
    {
        case DUNN_FIREWALL_ACTIVE:

            printf(GREEN "Firewall : ACTIVE\n" RESET);
            break;


        case DUNN_FIREWALL_INACTIVE:

            printf(RED "Firewall : INACTIVE\n" RESET);
            break;


        case DUNN_FIREWALL_UNKNOWN:
        default:

            printf("Firewall : UNKNOWN\n");
            break;
    }


    printf("Discovery: %s\n",
           discovery_result_name(snapshot->firewall_result));


    printf("Logging  : %s\n",
           snapshot->status.logging[0]
               ? snapshot->status.logging
               : "Unknown");


    printf("\nPOLICY\n");
    separator();


    printf("Incoming : %s\n",
           snapshot->status.incoming_policy[0]
               ? snapshot->status.incoming_policy
               : "Unknown");


    printf("Outgoing : %s\n",
           snapshot->status.outgoing_policy[0]
               ? snapshot->status.outgoing_policy
               : "Unknown");


    printf("Routed   : %s\n",
           snapshot->status.routed_policy[0]
               ? snapshot->status.routed_policy
               : "Unknown");
}


static void display_rules(
        const DunnSnapshot *snapshot)
{
    printf("\nFIREWALL RULES\n");
    separator();


    printf("Discovery: %s\n",
           discovery_result_name(snapshot->rules_result));


    printf("%-4s %-15s %-10s %-10s %-20s\n",
           "ID",
           "Destination",
           "Action",
           "Direction",
           "Source");


    for (size_t i = 0;
         i < snapshot->rule_count;
         i++)
    {
        const DunnFirewallRule *rule =
            &snapshot->rules[i];


        printf("%-4d %-15s %-10s %-10s %-20s\n",
               rule->id,
               rule->destination,
               rule->action,
               rule->direction,
               rule->source);
    }
}


static void display_ports(
        const DunnSnapshot *snapshot)
{
    printf("\nLISTENING PORTS\n");
    separator();


    printf("Discovery: %s\n",
           discovery_result_name(snapshot->ports_result));


    if (snapshot->port_count == 0)
    {
        if (snapshot->ports_result == DUNN_DISCOVERY_OK)
        {
            printf("No listening ports discovered.\n");
        }
        else
        {
            printf("Listening ports could not be established.\n");
        }

        return;
    }


    printf("%-8s %-8s %-40s %-20s %-8s\n",
           "PORT",
           "PROTOCOL",
           "ADDRESS",
           "PROCESS",
           "PID");


    for (size_t i = 0;
         i < snapshot->port_count;
         i++)
    {
        const DunnListeningPort *port =
            &snapshot->ports[i];


        printf("%-8d %-8s %-40s %-20s %-8d\n",
               port->port,
               port->protocol,
               port->address,
               port->process,
               port->pid);
    }
}


void dunn_display_snapshot(
        const DunnSnapshot *snapshot)
{
    if (!snapshot)
        return;


    display_banner();

    display_system(snapshot);

    display_firewall(snapshot);

    display_rules(snapshot);

    display_ports(snapshot);


    printf("\n");
}
