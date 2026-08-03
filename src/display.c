/*
 * DUNN - Firewall Security Monitor
 *
 * src/display.c
 */

#include <stdio.h>

#include "dunn.h"


#define CYAN  "\033[36m"
#define GREEN "\033[32m"
#define RESET "\033[0m"


static void separator(void)
{
    printf("--------------------------------------------\n");
}



void dunn_display_snapshot(
        const DunnSnapshot *snapshot)
{

    printf(CYAN);
    printf("\n");
    printf("============================================\n");
    printf("        DUNN Firewall Security Monitor\n");
    printf("============================================\n");
    printf(RESET);


    printf("\nSTATUS\n");
    separator();


    if (snapshot->status.active)
        printf(GREEN "Firewall : ACTIVE\n" RESET);
    else
        printf("Firewall : INACTIVE\n");


    printf("Logging  : %s\n",
           snapshot->status.logging);


    printf("\nPOLICY\n");
    separator();


    printf("Incoming : %s\n",
           snapshot->status.incoming_policy);

    printf("Outgoing : %s\n",
           snapshot->status.outgoing_policy);

    printf("Routed   : %s\n",
           snapshot->status.routed_policy);



    printf("\nRULES\n");
    separator();


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
        const DunnFirewallRule *r =
              &snapshot->rules[i];


        printf("%-4d %-15s %-10s %-10s %-20s\n",
               r->id,
               r->destination,
               r->action,
               r->direction,
               r->source);
    }



    printf("\nPORTS\n");
    separator();


    if (snapshot->port_count == 0)
    {
        printf("No port inspection yet.\n");
    }
}
