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
#define DUNN_MAX_BACKENDS 4


/*
 * Discovery results
 *
 * Each inspection operation has an independent result.
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
 *
 * DUNN_BACKEND_NONE is an aggregate result:
 * no supported backend was detected.
 *
 * It is not an individual backend to inspect.
 */

typedef enum
{
    DUNN_BACKEND_UNKNOWN = 0,
    DUNN_BACKEND_NONE,
    DUNN_BACKEND_UFW,
    DUNN_BACKEND_NFTABLES,
    DUNN_BACKEND_FIREWALLD,
    DUNN_BACKEND_IPTABLES

} DunnFirewallBackend;


/*
 * Backend installation state
 */

typedef enum
{
    DUNN_INSTALLATION_UNKNOWN = 0,
    DUNN_INSTALLATION_NOT_INSTALLED,
    DUNN_INSTALLATION_INSTALLED

} DunnInstallationState;


/*
 * Backend service state
 *
 * Some backends do not use a dedicated service.
 */

typedef enum
{
    DUNN_SERVICE_UNKNOWN = 0,
    DUNN_SERVICE_NOT_APPLICABLE,
    DUNN_SERVICE_INACTIVE,
    DUNN_SERVICE_ACTIVE

} DunnServiceState;


/*
 * Firewall ruleset state
 */

typedef enum
{
    DUNN_RULESET_UNKNOWN = 0,
    DUNN_RULESET_NOT_APPLICABLE,
    DUNN_RULESET_EMPTY,
    DUNN_RULESET_PRESENT

} DunnRulesetState;


/*
 * Firewall enforcement state
 *
 * Enforcement must not be inferred merely from:
 * - package installation;
 * - service activity;
 * - executable availability;
 * - the existence of a ruleset.
 */

typedef enum
{
    DUNN_ENFORCEMENT_UNKNOWN = 0,
    DUNN_ENFORCEMENT_NOT_ESTABLISHED,
    DUNN_ENFORCEMENT_ESTABLISHED

} DunnEnforcementState;


/*
 * Firewall operational state
 *
 * Retained for the existing global firewall status.
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
 * Individual firewall backend information
 *
 * Each supported backend is inspected independently.
 *
 * The executable and version fields are informational.
 * Their presence does not establish firewall enforcement.
 */

typedef struct
{
    DunnFirewallBackend backend;

    DunnInstallationState installation;
    DunnServiceState service;
    DunnRulesetState ruleset;
    DunnEnforcementState enforcement;

    char executable[128];
    char version[64];

    DunnDiscoveryResult discovery_result;

} DunnFirewallBackendInfo;


/*
 * Firewall global state
 *
 * Retained for compatibility with the existing UFW
 * status collector and display implementation.
 */

typedef struct
{
    DunnFirewallBackend backend;
    DunnFirewallState state;

    /*
     * Temporary compatibility field.
     * To be removed when all collectors use state.
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

    /*
     * Independent backend discovery.
     *
     * The entries describe detected backends.
     * Multiple entries may be present simultaneously.
     */

    DunnFirewallBackendInfo backends[DUNN_MAX_BACKENDS];
    size_t backend_count;

    DunnFirewallBackend aggregate_backend;

    DunnDiscoveryResult backend_result;

    DunnFirewallRule rules[DUNN_MAX_RULES];
    size_t rule_count;

    DunnListeningPort ports[DUNN_MAX_PORTS];
    size_t port_count;

    /*
     * Individual discovery outcomes.
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
 * Firewall backend reconnaissance
 *
 * Inspects supported backends independently.
 * Must remain read-only.
 */

DunnDiscoveryResult dunn_rekon_firewall_backends(
        DunnFirewallBackendInfo *backends,
        size_t max_backends,
        size_t *count);


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
