# Playbooks
<!-- group: Deploy and patch; order: 36; pages: /playbooks -->

A playbook runs several steps in order on a group of endpoints: tell people, patch, run a restart action, then check a service is back. Run it on demand, on a schedule, or when something happens.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`).
- Create the computer group the playbook will target. See [Computer groups](computer-groups.md).

## Create a playbook

1. Open **Playbooks**. Under **New playbook**, enter a name and description, the operating system and the target computer group.
2. Choose **Add step** for each step, and pick its kind:
   - **Apply patches**: install pending updates.
   - **Run a package**: install, update or remove a software package, or run an action package (for example one that restarts a service or the computer).
   - **Run an Enforce policy**: apply a setting and check it held.
   - **Check (gate)**: continue only on endpoints where a condition is true, for example a service is running.
   - **Notify the person**: show the signed-in user a message.
   - **Wait**: pause for a set time.
   - **Wait for approval**: pause until someone approves.
3. For each step, choose what happens if it fails on an endpoint: stop that endpoint's run, or carry on.
4. Use **↑** and **↓** to reorder steps.
5. Set the schedule (**Daily** or **Weekly**, with a time), or leave the playbook disabled to run it only by hand.
6. Choose **Save playbook**.

**Load the patch-and-reboot example** fills in a typical playbook to start from.

## Run it now

Choose **Run now** on the playbook. **Runs** shows each run; **Open** one to see every endpoint's progress through the steps.

## Start it automatically

**Playbooks → Triggers → Create trigger** starts a playbook when:

- **A Guide item is raised** (for example "critical vulnerability on this endpoint"), or
- **Something posts to a URL**: another system calls the trigger's webhook URL. The URL contains its own secret; treat it like a password.

## Approvals

A step that needs approval waits under **Waiting for approval**. Someone with **Decide approvals** chooses **Approve** or **Reject**. The person who started the run cannot approve their own.

## If something goes wrong

- **A run is stuck:** it may be waiting for a maintenance window or an approval. Open the run to see which step each endpoint is on.
- **The target group was deleted:** the playbook stops rather than running everywhere. Choose another group and save.
