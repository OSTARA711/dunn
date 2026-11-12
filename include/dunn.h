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
 * Discovery results
 *
 * These values describe the outcome of an inspection operation.
 * A discovery failure must not automatically terminate DUNN.
 */

typedef enum
{
    DUNN_DISCOVERY_NOT_RUN = 0,
    DUNN_DISCOVERY_OK,
    DUNN_DISCOVERY_PARTIAL,
    DUNN_DISCOVERY_UNAVAILABLE,
    DUNN_DISCOVERY_PERMISSION_DENIED,
    DUNN_DISCOVERY_FAILED

} DunnDiscoveryResult;


/*
 * Firewall backends
 */

typedef enum
{
    DUNN_BACKEND_UNKNOWN = 0,
    DUNN_BACKEND_NONE,
    DUNN_BACKEND_UFW,
    DUNN_BACKEND_NFTABLES,
    DUNN_BACKEND_FIREWALLD

} DunnFirewallBackend;


/*
 * Firewall operational state
 */

typedef enum
{
    DUNN_FIREWALL_UNKNOWN = 0,
    DUNN_FIREWALL_INACTIVE,
    DUNN_FIREWALL_ACTIVE

} DunnFirewallState;


/*
 * Operating system and kernel information
 */

typedef struct
{
    char os_name[128];
    char os_version[64];

    char kernel_name[64];
    char kernel_release[128];
    char architecture[64];

} DunnSystemInfo;


/*
 * Firewall global state
 */

typedef struct
{
    DunnFirewallBackend backend;
    DunnFirewallState state;

    /*
     * Retained temporarily for compatibility with display.c.
     * Will be removed when display.c migrates to state.
     */

    int active;

    char logging[32];

    char incoming_policy[32];
    char outgoing_policy[32];
    char routed_policy[32];

} DunnFirewallStatus;


/*
 * Firewall rule
 *
 * Currently populated by the UFW-specific collector.
 * This representation will be reviewed before implementing
 * native nftables rule inspection.
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
 * Complete system and firewall snapshot
 */

typedef struct
{
    DunnSystemInfo system;

    DunnFirewallStatus status;

    DunnFirewallRule rules[DUNN_MAX_RULES];
    size_t rule_count;

    DunnListeningPort ports[DUNN_MAX_PORTS];
    size_t port_count;

    /*
     * Individual discovery outcomes.
     *
     * Each operation can succeed or fail independently.
     */

    DunnDiscoveryResult system_result;
    DunnDiscoveryResult firewall_result;
    DunnDiscoveryResult rules_result;
    DunnDiscoveryResult ports_result;

} DunnSnapshot;


/*
 * System reconnaissance
 */

DunnDiscoveryResult dunn_rekon_system(
        DunnSystemInfo *system);


/*
 * Existing UFW-specific collectors
 *
 * Retained during the transition to backend-independent
 * firewall discovery.
 */

int dunn_get_ufw_status(
        DunnFirewallStatus *status);

int dunn_get_ufw_rules(
        DunnFirewallRule *rules,
        size_t max_rules,
        size_t *count);


/*
 * Listening-port discovery
 */

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
