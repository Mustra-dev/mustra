# Access control
<!-- group: Start here; order: 4; pages: /access -->

Go beyond roles: limit what part of the fleet a role may act on, keep sensitive endpoints out of a module's reach, require a second person's approval, and grant time-boxed access to an endpoint.

## Before you start

- Most of this page needs **Manage settings** (`settings.manage`). Deciding approvals needs **Decide approvals**; granting endpoint access needs **Approve endpoint access**.
- Everything here defaults to "no limit", so nothing changes until you configure it.

## Limit a role to part of the fleet (management rights)

A role can be limited to computer groups: its holders may act only on endpoints in those groups.

1. Edit the role under **Administration → Roles** and choose its computer groups.
2. An operation on an endpoint outside the scope is refused and names the endpoint. A fleet-wide operation is narrowed to the scope and says how many it left out.

**Your scope** on this page shows what the signed-in person may act on.

## Keep endpoints out of a module's reach (action groups)

An action group is a ceiling on a module, for everybody including administrators. For example: Deploy may never act on domain controllers.

1. **Access → Action Groups**, under **Set a module's ceiling**, choose the module (Deploy, Patch, Playbooks, Direct Connect, Enforce, Reveal) and the computer groups it may act on.
2. Choose **Save action group**. **Remove cap** lifts it.

## Limit what a role may use (content sets)

A content set names packages, dashboards, saved questions and sensors. A role holding a content set may use only what is in it.

1. **Access → Content Sets → New content set**, pick its contents, **Save content set**.
2. Attach it to roles under **Administration → Roles**.

## Require a second person (approval policies)

1. **Access → Approval Policies → New approval policy**.
2. Choose which operations need approval (for example deployments to servers), and save.
3. A matching operation waits under **Access → Approvals** until someone with **Decide approvals** chooses **Approve** or **Deny**. Nobody can approve their own.

## Time-boxed access to an endpoint (Jump Gate)

Jump Gate lets someone open a remote session on an endpoint for a limited time, with a reason and, if you choose, an approval.

1. **Access → Jump Gate → Jump policies → New jump policy**: the endpoints it covers, whether a reason and approval are required, and the longest time allowed.
2. People request access from the endpoint; requests appear under **Access requests**.
3. **Sessions** lists recorded sessions; choose **Transcript** to read what was done, or **Revoke** to end access early.
