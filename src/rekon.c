/*
 * DUNN - Firewall Security Monitor
 *
 * src/rekon.c
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "dunn.h"


#define DUNN_COMMAND_OUTPUT_SIZE 8192
#define DUNN_EXECUTABLE_SIZE 256


extern char **environ;


/*
 * Copy and decode a value from os-release.
 *
 * The file is read as data, never executed as a shell script.
 */

static void copy_os_value(
        char *destination,
        size_t destination_size,
        const char *value)
{
    size_t length = 0;
    char quote = '\0';


    if (!destination || destination_size == 0 || !value)
        return;


    destination[0] = '\0';


    while (isspace((unsigned char)*value))
        value++;


    if (*value == '"' || *value == '\'')
    {
        quote = *value;
        value++;
    }


    while (*value && length < destination_size - 1)
    {
        if (quote)
        {
            if (*value == quote)
                break;


            if (quote == '"' && *value == '\\' && value[1])
            {
                char escaped = value[1];

                if (escaped == '\\' ||
                    escaped == '"' ||
                    escaped == '$' ||
                    escaped == '`')
                {
                    destination[length++] = escaped;
                    value += 2;
                    continue;
                }
            }
        }
        else
        {
            if (isspace((unsigned char)*value) ||
                *value == '#')
            {
                break;
            }
        }


        destination[length++] = *value++;
    }


    destination[length] = '\0';
}


/*
 * Read one os-release file.
 *
 * Returns:
 *   1  Information was found.
 *   0  No recognised information was found.
 *  -1  File could not be opened or read.
 */

static int read_os_release_file(
        const char *path,
        char *pretty_name,
        size_t pretty_name_size,
        char *name,
        size_t name_size,
        char *version,
        size_t version_size)
{
    FILE *fp;

    char line[512];
    char *separator;

    int found = 0;


    fp = fopen(path, "r");

    if (!fp)
        return -1;


    while (fgets(line, sizeof(line), fp))
    {
        if (line[0] == '#' || line[0] == '\n')
            continue;


        separator = strchr(line, '=');

        if (!separator)
            continue;


        *separator = '\0';

        const char *value = separator + 1;


        if (strcmp(line, "PRETTY_NAME") == 0)
        {
            copy_os_value(
                    pretty_name,
                    pretty_name_size,
                    value);

            found = pretty_name[0] != '\0' || found;
        }
        else if (strcmp(line, "NAME") == 0)
        {
            copy_os_value(
                    name,
                    name_size,
                    value);

            found = name[0] != '\0' || found;
        }
        else if (strcmp(line, "VERSION_ID") == 0)
        {
            copy_os_value(
                    version,
                    version_size,
                    value);

            found = version[0] != '\0' || found;
        }
    }


    int read_error = ferror(fp);

    fclose(fp);


    if (read_error)
        return -1;


    return found;
}


/*
 * Read operating system information.
 *
 * /etc/os-release is preferred.
 * /usr/lib/os-release is used as a fallback.
 */

static int read_os_release(DunnSystemInfo *system)
{
    char pretty_name[128] = "";
    char name[128] = "";
    char version[64] = "";

    int result;


    result = read_os_release_file(
            "/etc/os-release",
            pretty_name,
            sizeof(pretty_name),
            name,
            sizeof(name),
            version,
            sizeof(version));


    if (result < 0)
    {
        result = read_os_release_file(
                "/usr/lib/os-release",
                pretty_name,
                sizeof(pretty_name),
                name,
                sizeof(name),
                version,
                sizeof(version));
    }


    if (result <= 0)
        return result;


    if (pretty_name[0] != '\0')
    {
        snprintf(
                system->os_name,
                sizeof(system->os_name),
                "%s",
                pretty_name);
    }
    else
    {
        snprintf(
                system->os_name,
                sizeof(system->os_name),
                "%s",
                name);
    }


    snprintf(
            system->os_version,
            sizeof(system->os_version),
            "%s",
            version);


    return 1;
}


/*
 * System reconnaissance.
 *
 * Collects distribution and kernel information.
 */

DunnDiscoveryResult dunn_rekon_system(
        DunnSystemInfo *system)
{
    struct utsname information;

    int os_result;


    if (!system)
        return DUNN_DISCOVERY_FAILED;


    memset(system, 0, sizeof(*system));


    os_result = read_os_release(system);


    if (uname(&information) != 0)
        return DUNN_DISCOVERY_FAILED;


    snprintf(
            system->kernel_name,
            sizeof(system->kernel_name),
            "%.*s",
            (int)sizeof(system->kernel_name) - 1,
            information.sysname);


    snprintf(
            system->kernel_release,
            sizeof(system->kernel_release),
            "%.*s",
            (int)sizeof(system->kernel_release) - 1,
            information.release);


    snprintf(
            system->architecture,
            sizeof(system->architecture),
            "%.*s",
            (int)sizeof(system->architecture) - 1,
            information.machine);


    if (os_result != 1 ||
        system->os_name[0] == '\0' ||
        system->os_version[0] == '\0')
    {
        return DUNN_DISCOVERY_PARTIAL;
    }


    return DUNN_DISCOVERY_OK;
}


/* ============================================================
 * FIREWALL BACKEND RECONNAISSANCE
 * ============================================================ */


/*
 * Locate an executable using PATH.
 *
 * Returns:
 *   0  Executable found.
 *  -1  Executable not found.
 *
 * This checks executable availability, not package-manager
 * installation records.
 */

static int find_executable(
        const char *name,
        char *path,
        size_t path_size)
{
    const char *environment_path;
    const char *position;

    char candidate[DUNN_EXECUTABLE_SIZE];

    size_t directory_length;
    size_t name_length;


    if (!name || !path || path_size == 0)
        return -1;


    path[0] = '\0';

    environment_path = getenv("PATH");


    if (!environment_path)
    {
        environment_path =
            "/usr/local/sbin:/usr/local/bin:"
            "/usr/sbin:/usr/bin:/sbin:/bin";
    }


    position = environment_path;
    name_length = strlen(name);


    while (1)
    {
        const char *separator = strchr(position, ':');

        directory_length = separator
            ? (size_t)(separator - position)
            : strlen(position);


        if (directory_length == 0)
        {
            snprintf(
                    candidate,
                    sizeof(candidate),
                    "./%s",
                    name);
        }
        else
        {
            if (directory_length + name_length + 2 >
                sizeof(candidate))
            {
                if (!separator)
                    break;

                position = separator + 1;
                continue;
            }


            memcpy(candidate, position, directory_length);

            candidate[directory_length] = '/';

            memcpy(
                    candidate + directory_length + 1,
                    name,
                    name_length + 1);
        }


        if (access(candidate, X_OK) == 0)
        {
            snprintf(
                    path,
                    path_size,
                    "%s",
                    candidate);

            return 0;
        }


        if (!separator)
            break;


        position = separator + 1;
    }


    return -1;
}


/*
 * Execute a fixed executable with an argument array.
 *
 * No shell is invoked.
 *
 * Standard output and standard error are captured together.
 *
 * Returns:
 *   0  Command succeeded.
 *   1  Command failed.
 *   2  Permission denied.
 *  -1  Execution or I/O failure.
 */

static int run_probe(
        const char *executable,
        char *const arguments[],
        char *output,
        size_t output_size)
{
    int pipe_fd[2];

    posix_spawn_file_actions_t actions;

    pid_t child;

    int child_status;
    int spawn_error;
    int action_error = 0;

    size_t used = 0;

    ssize_t bytes;

    int truncated = 0;


    if (!executable ||
        !arguments ||
        !arguments[0] ||
        !output ||
        output_size < 2)
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


    action_error |= posix_spawn_file_actions_adddup2(
            &actions,
            pipe_fd[1],
            STDOUT_FILENO);

    action_error |= posix_spawn_file_actions_adddup2(
            &actions,
            pipe_fd[1],
            STDERR_FILENO);

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


    spawn_error = posix_spawn(
            &child,
            executable,
            &actions,
            NULL,
            arguments,
            environ);


    posix_spawn_file_actions_destroy(&actions);

    close(pipe_fd[1]);


    if (spawn_error != 0)
    {
        close(pipe_fd[0]);

        if (spawn_error == EACCES ||
            spawn_error == EPERM)
        {
            return 2;
        }

        return -1;
    }


    /*
     * Read the complete output while retaining only
     * the portion that fits in the output buffer.
     */

    while (1)
    {
        char discard[512];

        void *destination;
        size_t available;


        if (used < output_size - 1)
        {
            destination = output + used;
            available = output_size - used - 1;
        }
        else
        {
            destination = discard;
            available = sizeof(discard);
            truncated = 1;
        }


        bytes = read(
                pipe_fd[0],
                destination,
                available);


        if (bytes > 0)
        {
            if (!truncated)
                used += (size_t)bytes;

            continue;
        }


        if (bytes == 0)
            break;


        if (errno == EINTR)
            continue;


        close(pipe_fd[0]);

        while (waitpid(child, NULL, 0) < 0 &&
               errno == EINTR)
        {
        }

        return -1;
    }


    close(pipe_fd[0]);

    output[used] = '\0';


    while (waitpid(child, &child_status, 0) < 0)
    {
        if (errno != EINTR)
            return -1;
    }


    if (truncated)
        return -1;


    if (strstr(output, "Permission denied") ||
        strstr(output, "Operation not permitted"))
    {
        return 2;
    }


    if (!WIFEXITED(child_status))
        return -1;


    if (WEXITSTATUS(child_status) != 0)
        return 1;


    return 0;
}


/*
 * Copy the first output line into a version field.
 */

static void copy_first_line(
        char *destination,
        size_t destination_size,
        const char *output)
{
    size_t length = 0;


    if (!destination || destination_size == 0)
        return;


    destination[0] = '\0';


    if (!output)
        return;


    while (output[length] &&
           output[length] != '\n' &&
           output[length] != '\r' &&
           length < destination_size - 1)
    {
        destination[length] = output[length];
        length++;
    }


    destination[length] = '\0';
}


/*
 * Determine whether command output contains non-whitespace.
 */

static int output_has_content(const char *output)
{
    if (!output)
        return 0;


    while (*output)
    {
        if (!isspace((unsigned char)*output))
            return 1;

        output++;
    }


    return 0;
}


/*
 * Initialise one backend record.
 */

static void initialise_backend(
        DunnFirewallBackendInfo *backend,
        DunnFirewallBackend type)
{
    memset(backend, 0, sizeof(*backend));

    backend->backend = type;

    backend->installation = DUNN_INSTALLATION_UNKNOWN;
    backend->service = DUNN_SERVICE_UNKNOWN;
    backend->ruleset = DUNN_RULESET_UNKNOWN;
    backend->enforcement = DUNN_ENFORCEMENT_UNKNOWN;

    backend->discovery_result = DUNN_DISCOVERY_NOT_RUN;
}


/*
 * Inspect UFW.
 *
 * UFW is a firewall management frontend. Its status is
 * inspected separately from the underlying nftables rules.
 */

static void rekon_ufw(
        DunnFirewallBackendInfo *backend)
{
    char output[DUNN_COMMAND_OUTPUT_SIZE];

    char version_output[256];

    char *version_arguments[] =
    {
        "ufw",
        "version",
        NULL
    };

    char *status_arguments[] =
    {
        "ufw",
        "status",
        "verbose",
        NULL
    };

    int result;


    if (find_executable(
                "ufw",
                backend->executable,
                sizeof(backend->executable)) != 0)
    {
        backend->installation = DUNN_INSTALLATION_NOT_INSTALLED;
        backend->service = DUNN_SERVICE_NOT_APPLICABLE;
        backend->discovery_result = DUNN_DISCOVERY_OK;
        return;
    }


    backend->installation = DUNN_INSTALLATION_INSTALLED;
    backend->service = DUNN_SERVICE_NOT_APPLICABLE;


    result = run_probe(
            backend->executable,
            version_arguments,
            version_output,
            sizeof(version_output));


    if (result == 0)
    {
        copy_first_line(
                backend->version,
                sizeof(backend->version),
                version_output);
    }


    result = run_probe(
            backend->executable,
            status_arguments,
            output,
            sizeof(output));


    if (result == 2)
    {
        backend->discovery_result =
            DUNN_DISCOVERY_PERMISSION_DENIED;
        return;
    }


    if (result != 0)
    {
        backend->discovery_result = DUNN_DISCOVERY_FAILED;
        return;
    }


    if (strstr(output, "Status: active") ||
        strstr(output, "Status: inactive"))
    {
        backend->discovery_result = DUNN_DISCOVERY_OK;
    }
    else
    {
        backend->discovery_result = DUNN_DISCOVERY_PARTIAL;
    }
}


/*
 * Inspect nftables.
 *
 * The ruleset is read using "nft list ruleset".
 * No rules are added, deleted or changed.
 */

static void rekon_nftables(
        DunnFirewallBackendInfo *backend)
{
    char output[DUNN_COMMAND_OUTPUT_SIZE];

    char version_output[256];

    char *version_arguments[] =
    {
        "nft",
        "--version",
        NULL
    };

    char *ruleset_arguments[] =
    {
        "nft",
        "list",
        "ruleset",
        NULL
    };

    int result;


    if (find_executable(
                "nft",
                backend->executable,
                sizeof(backend->executable)) != 0)
    {
        backend->installation = DUNN_INSTALLATION_NOT_INSTALLED;
        backend->service = DUNN_SERVICE_NOT_APPLICABLE;
        backend->discovery_result = DUNN_DISCOVERY_OK;
        return;
    }


    backend->installation = DUNN_INSTALLATION_INSTALLED;
    backend->service = DUNN_SERVICE_NOT_APPLICABLE;


    result = run_probe(
            backend->executable,
            version_arguments,
            version_output,
            sizeof(version_output));


    if (result == 0)
    {
        copy_first_line(
                backend->version,
                sizeof(backend->version),
                version_output);
    }


    result = run_probe(
            backend->executable,
            ruleset_arguments,
            output,
            sizeof(output));


    if (result == 2)
    {
        backend->discovery_result =
            DUNN_DISCOVERY_PERMISSION_DENIED;
        return;
    }


    if (result != 0)
    {
        backend->discovery_result = DUNN_DISCOVERY_FAILED;
        return;
    }


    backend->ruleset = output_has_content(output)
        ? DUNN_RULESET_PRESENT
        : DUNN_RULESET_EMPTY;


    backend->discovery_result = DUNN_DISCOVERY_OK;
}


/*
 * Inspect firewalld.
 *
 * firewall-cmd --state reports whether the daemon is running.
 * This does not by itself prove that traffic is being filtered.
 */

static void rekon_firewalld(
        DunnFirewallBackendInfo *backend)
{
    char output[1024];

    char version_output[256];

    char *version_arguments[] =
    {
        "firewall-cmd",
        "--version",
        NULL
    };

    char *state_arguments[] =
    {
        "firewall-cmd",
        "--state",
        NULL
    };

    int result;


    if (find_executable(
                "firewall-cmd",
                backend->executable,
                sizeof(backend->executable)) != 0)
    {
        backend->installation = DUNN_INSTALLATION_NOT_INSTALLED;
        backend->service = DUNN_SERVICE_UNKNOWN;
        backend->discovery_result = DUNN_DISCOVERY_OK;
        return;
    }


    backend->installation = DUNN_INSTALLATION_INSTALLED;


    result = run_probe(
            backend->executable,
            version_arguments,
            version_output,
            sizeof(version_output));


    if (result == 0)
    {
        copy_first_line(
                backend->version,
                sizeof(backend->version),
                version_output);
    }


    result = run_probe(
            backend->executable,
            state_arguments,
            output,
            sizeof(output));


    if (result == 0)
    {
        if (strstr(output, "running"))
        {
            backend->service = DUNN_SERVICE_ACTIVE;
            backend->discovery_result = DUNN_DISCOVERY_OK;
        }
        else
        {
            backend->service = DUNN_SERVICE_UNKNOWN;
            backend->discovery_result = DUNN_DISCOVERY_PARTIAL;
        }

        return;
    }


    if (result == 2)
    {
        backend->discovery_result =
            DUNN_DISCOVERY_PERMISSION_DENIED;
        return;
    }


    if (strstr(output, "not running"))
    {
        backend->service = DUNN_SERVICE_INACTIVE;
        backend->discovery_result = DUNN_DISCOVERY_OK;
        return;
    }


    backend->service = DUNN_SERVICE_UNKNOWN;
    backend->discovery_result = DUNN_DISCOVERY_PARTIAL;
}


/*
 * Inspect iptables.
 *
 * iptables may use either the legacy or nf_tables
 * kernel interface. The version output identifies this.
 */

static void rekon_iptables(
        DunnFirewallBackendInfo *backend)
{
    char output[DUNN_COMMAND_OUTPUT_SIZE];

    char version_output[256];

    char *version_arguments[] =
    {
        "iptables",
        "--version",
        NULL
    };

    char *ruleset_arguments[] =
    {
        "iptables-save",
        NULL
    };

    int result;


    if (find_executable(
                "iptables",
                backend->executable,
                sizeof(backend->executable)) != 0)
    {
        backend->installation = DUNN_INSTALLATION_NOT_INSTALLED;
        backend->service = DUNN_SERVICE_NOT_APPLICABLE;
        backend->discovery_result = DUNN_DISCOVERY_OK;
        return;
    }


    backend->installation = DUNN_INSTALLATION_INSTALLED;
    backend->service = DUNN_SERVICE_NOT_APPLICABLE;


    result = run_probe(
            backend->executable,
            version_arguments,
            version_output,
            sizeof(version_output));


    if (result != 0)
    {
        backend->discovery_result = DUNN_DISCOVERY_FAILED;
        return;
    }


    copy_first_line(
            backend->version,
            sizeof(backend->version),
            version_output);


    char save_executable[DUNN_EXECUTABLE_SIZE];


    if (find_executable(
                "iptables-save",
                save_executable,
                sizeof(save_executable)) != 0)
    {
        backend->discovery_result = DUNN_DISCOVERY_PARTIAL;
        return;
    }


    result = run_probe(
            save_executable,
            ruleset_arguments,
            output,
            sizeof(output));


    if (result == 2)
    {
        backend->discovery_result =
            DUNN_DISCOVERY_PERMISSION_DENIED;
        return;
    }


    if (result != 0)
    {
        backend->discovery_result = DUNN_DISCOVERY_FAILED;
        return;
    }


    backend->ruleset = output_has_content(output)
        ? DUNN_RULESET_PRESENT
        : DUNN_RULESET_EMPTY;


    backend->discovery_result = DUNN_DISCOVERY_OK;
}


/*
 * Independent firewall backend reconnaissance.
 *
 * Checks:
 * - UFW
 * - nftables
 * - firewalld
 * - iptables
 *
 * A missing executable is reported as not installed.
 * A failed inspection of one backend does not prevent
 * inspection of the remaining backends.
 *
 * This function is strictly read-only.
 */

DunnDiscoveryResult dunn_rekon_firewall_backends(
        DunnFirewallBackendInfo *backends,
        size_t max_backends,
        size_t *count)
{
    static const DunnFirewallBackend backend_types[] =
    {
        DUNN_BACKEND_UFW,
        DUNN_BACKEND_NFTABLES,
        DUNN_BACKEND_FIREWALLD,
        DUNN_BACKEND_IPTABLES
    };

    const size_t total_backends =
        sizeof(backend_types) / sizeof(backend_types[0]);

    size_t inspect_count;

    int partial = 0;


    if (!count || (!backends && max_backends > 0))
        return DUNN_DISCOVERY_FAILED;


    *count = 0;


    if (max_backends == 0)
        return DUNN_DISCOVERY_PARTIAL;


    inspect_count = max_backends < total_backends
        ? max_backends
        : total_backends;


    for (size_t i = 0; i < inspect_count; i++)
    {
        DunnFirewallBackendInfo *backend = &backends[i];

        initialise_backend(
                backend,
                backend_types[i]);


        switch (backend_types[i])
        {
            case DUNN_BACKEND_UFW:
                rekon_ufw(backend);
                break;

            case DUNN_BACKEND_NFTABLES:
                rekon_nftables(backend);
                break;

            case DUNN_BACKEND_FIREWALLD:
                rekon_firewalld(backend);
                break;

            case DUNN_BACKEND_IPTABLES:
                rekon_iptables(backend);
                break;

            default:
                backend->discovery_result =
                    DUNN_DISCOVERY_FAILED;
                break;
        }


        if (backend->discovery_result != DUNN_DISCOVERY_OK)
            partial = 1;


        (*count)++;
    }


    if (inspect_count < total_backends)
        partial = 1;


    return partial
        ? DUNN_DISCOVERY_PARTIAL
        : DUNN_DISCOVERY_OK;
}
