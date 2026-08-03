/*
 * DUNN - Firewall Security Monitor
 *
 * include/dunn.h
 */

#ifndef DUNN_H
#define DUNN_H

#include <stddef.h>


#define DUNN_VERSION "0.0.1"


#define DUNN_MAX_RULES 128
#define DUNN_MAX_PORTS 128


/*
 * Firewall global state
 */

typedef struct
{
    int active;

    char logging[32];

    char incoming_policy[32];
    char outgoing_policy[32];
    char routed_policy[32];

} DunnFirewallStatus;


/*
 * Firewall rule
 */

typedef struct
{
    int id;

    char destination[64];
    char action[32];
    char direction[16];
    char source[64];

} DunnFirewallRule;


/*
 * Listening service
 */

typedef struct
{
    int port;

    char protocol[8];
    char address[64];

    char process[128];

    int pid;

} DunnListeningPort;


/*
 * Complete firewall snapshot
 */

typedef struct
{
    DunnFirewallStatus status;

    DunnFirewallRule rules[DUNN_MAX_RULES];
    size_t rule_count;

    DunnListeningPort ports[DUNN_MAX_PORTS];
    size_t port_count;

} DunnSnapshot;


/*
 * Data collectors
 */

int dunn_get_ufw_status(DunnFirewallStatus *status);

int dunn_get_ufw_rules(
        DunnFirewallRule *rules,
        size_t max_rules,
        size_t *count);


int dunn_get_listening_ports(
        DunnListeningPort *ports,
        size_t max_ports,
        size_t *count);


/*
 * Display
 */

void dunn_display_snapshot(
        const DunnSnapshot *snapshot);


#endif
