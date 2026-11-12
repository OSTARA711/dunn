/*
 * DUNN - Firewall Security Monitor
 *
 * src/ufw.c
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dunn.h"


extern char **environ;


#define UFW_OUTPUT_SIZE 8192


/*
 * Execute a command without invoking a shell.
 *
 * Standard output is captured.
 * Standard error remains visible to the user.
 *
 * Returns:
 *   0  Command completed successfully.
 *  -1  Execution or command failure.
 */

static int run_command(
        char *const arguments[],
        char *output,
        size_t output_size)
{
    int pipe_fd[2];

    pid_t child;
    int child_status;

    posix_spawn_file_actions_t actions;

    size_t used = 0;
    int truncated = 0;

    ssize_t bytes;


    if (!arguments || !arguments[0] ||
        !output || output_size == 0)
    {
        return -1;
    }


    output[0] = '\0';


    if (pipe(pipe_fd) != 0)
        return -1;


    if (posix_spawn_file_actions_init(&actions) != 0)
    {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }


    int action_error = 0;

    action_error |= posix_spawn_file_actions_adddup2(
            &actions,
            pipe_fd[1],
            STDOUT_FILENO);

    action_error |= posix_spawn_file_actions_addclose(
            &actions,
            pipe_fd[0]);

    action_error |= posix_spawn_file_actions_addclose(
            &actions,
            pipe_fd[1]);


    if (action_error != 0)
    {
        posix_spawn_file_actions_destroy(&actions);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }


    int spawn_error = posix_spawnp(
            &child,
            arguments[0],
            &actions,
            NULL,
            arguments,
            environ);


    posix_spawn_file_actions_destroy(&actions);

    close(pipe_fd[1]);


    if (spawn_error != 0)
    {
        close(pipe_fd[0]);
        return -1;
    }


    /*
     * Read command output.
     *
     * Continue draining the pipe if the output buffer
     * becomes full, preventing the child from blocking.
     */

    while ((bytes = read(
                    pipe_fd[0],
                    output + used,
                    output_size - used - 1)) != 0)
    {
        if (bytes < 0)
        {
            if (errno == EINTR)
                continue;

            close(pipe_fd[0]);

            while (waitpid(child, NULL, 0) < 0 &&
                   errno == EINTR)
            {
            }

            return -1;
        }


        used += (size_t)bytes;


        if (used >= output_size - 1)
        {
            truncated = 1;

            char discard[512];

            while ((bytes = read(
                            pipe_fd[0],
                            discard,
                            sizeof(discard))) > 0)
            {
            }

            break;
        }
    }


    close(pipe_fd[0]);

    output[used] = '\0';


    /*
     * Check the actual child exit status.
     */

    while (waitpid(child, &child_status, 0) < 0)
    {
        if (errno != EINTR)
            return -1;
    }


    if (truncated ||
        !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0)
    {
        return -1;
    }


    return 0;
}


/*
 * Remove trailing newline and carriage-return characters.
 */

static void trim_line(char *line)
{
    size_t length = strlen(line);


    while (length > 0 &&
           (line[length - 1] == '\n' ||
            line[length - 1] == '\r'))
    {
        line[--length] = '\0';
    }
}


/*
 * Retrieve UFW firewall status.
 *
 * Does not install, enable, disable or modify UFW.
 */

int dunn_get_ufw_status(DunnFirewallStatus *status)
{
    char output[UFW_OUTPUT_SIZE];

    char *arguments[] =
    {
        "ufw",
        "status",
        "verbose",
        NULL
    };


    if (!status)
        return -1;


    memset(status, 0, sizeof(*status));

    status->backend = DUNN_BACKEND_UNKNOWN;
    status->state = DUNN_FIREWALL_UNKNOWN;


    if (run_command(
                arguments,
                output,
                sizeof(output)) != 0)
    {
        return -1;
    }


    /*
     * A successful command execution alone is insufficient.
     * We must also recognise a valid UFW status response.
     */

    if (strstr(output, "Status: active"))
    {
        status->state = DUNN_FIREWALL_ACTIVE;
        status->active = 1;
    }
    else if (strstr(output, "Status: inactive"))
    {
        status->state = DUNN_FIREWALL_INACTIVE;
        status->active = 0;
    }
    else
    {
        return -1;
    }


    status->backend = DUNN_BACKEND_UFW;


    /*
     * Extract logging and default policies.
     */

    char *line = strtok(output, "\n");

    while (line)
    {
        trim_line(line);


        if (strncmp(line, "Logging:", 8) == 0)
        {
            sscanf(
                    line,
                    "Logging: %31[^\n]",
                    status->logging);
        }


        else if (strncmp(line, "Default:", 8) == 0)
        {
            sscanf(
                    line,
                    "Default: %31[^,], %31[^,], %31[^\n]",
                    status->incoming_policy,
                    status->outgoing_policy,
                    status->routed_policy);
        }


        line = strtok(NULL, "\n");
    }


    return 0;
}


/*
 * Retrieve numbered UFW firewall rules.
 *
 * This collector only understands UFW's rule format.
 * Native nftables inspection requires a separate collector.
 */

int dunn_get_ufw_rules(
        DunnFirewallRule *rules,
        size_t max_rules,
        size_t *count)
{
    char output[UFW_OUTPUT_SIZE];

    char *arguments[] =
    {
        "ufw",
        "status",
        "numbered",
        NULL
    };


    if (!count || (!rules && max_rules > 0))
        return -1;


    *count = 0;


    if (max_rules == 0)
        return 0;


    if (run_command(
                arguments,
                output,
                sizeof(output)) != 0)
    {
        return -1;
    }


    char *line = strtok(output, "\n");

    while (line && *count < max_rules)
    {
        if (line[0] == '[')
        {
            DunnFirewallRule rule;

            memset(&rule, 0, sizeof(rule));


            int fields = sscanf(
                    line,
                    "[ %d] %63s %31s %15s %63[^\n]",
                    &rule.id,
                    rule.destination,
                    rule.action,
                    rule.direction,
                    rule.source);


            if (fields >= 4)
            {
                rules[*count] = rule;
                (*count)++;
            }
        }


        line = strtok(NULL, "\n");
    }


    return 0;
}


/*
 * Listening-port discovery is not a UFW operation.
 *
 * This placeholder deliberately reports failure rather
 * than claiming that no listening ports were discovered.
 *
 * It will be implemented separately using ss or /proc/net.
 */

int dunn_get_listening_ports(
        DunnListeningPort *ports,
        size_t max_ports,
        size_t *count)
{
    (void)ports;
    (void)max_ports;


    if (!count)
        return -1;


    *count = 0;

    return -1;
}
