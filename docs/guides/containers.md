# Containers
<!-- group: See your fleet; order: 27; pages: /containers -->

See every Docker and Podman container across your endpoints, and which images have an update. mustra only reports: it does not pull images or restart containers.

## Before you start

- Reading needs **See the fleet**.
- Install the agent on each container host, and upgrade existing agents. Containers are read on Linux, and on Macs where Docker's default socket is turned on.
- Each host needs HTTPS access to the registries its images came from.

## Find what needs updating

1. Open **Containers**. Containers with an update are listed first.
2. Turn on **Only containers with an update** to hide the rest.
3. Read the line under the status. A version tag shows what it could move to, such as the newest in its major version and the newest overall. Otherwise it says why the status is what it is.
4. Update the container your usual way. The page catches up on the agent's next checks, up to about seven hours later.

## What each status means

| Status | Meaning |
| --- | --- |
| **Update available** | The tag now points to a different image, or a newer version tag exists. |
| **Up to date** | The registry confirmed the image is current, and no newer version tag exists. |
| **Could not check** | The registry refused or did not answer. Private images show this, because checks are anonymous. |
| **Not checked** | There is nothing to compare: the image was built locally or is pinned by digest, the first check has not run, or checks are off. |

## Use the data elsewhere

- **API:** `GET /api/containers?update=update_available` returns the same list, for a script to act on.
- **AI agents:** see below.
- **Computer groups and Interact:** use the fields such as `containers.update` and `containers.image`.

## Stop registry checks

Start the agent with `--no-container-update-checks`, or set `MUSTRA_NO_CONTAINER_UPDATE_CHECKS=1`, to keep the inventory without contacting registries. Its containers then show **Not checked**.

## Connect an AI agent

mustra has a read-only MCP endpoint, so an AI agent can ask what has updates outstanding and act with its own tools. mustra itself changes nothing.

1. Create an API token with only **See the fleet** (`fleet.read`). See [Automate with the API](api.md).
2. Add the endpoint to your agent as a remote MCP server, using Streamable HTTP. For example, in Claude Code:

   ```
   claude mcp add --transport http mustra https://mustra.example.com/api/mcp --header "Authorization: Bearer $MUSTRA_TOKEN"
   ```

3. Ask it something like "which containers have updates outstanding?"

It has one tool, `list_containers`, which filters by update status, hostname or endpoint.
