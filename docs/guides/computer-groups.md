# Computer groups
<!-- group: Manage endpoints; order: 12; pages: /groups -->

A computer group is a named slice of the fleet, such as "Windows laptops" or "Linux web servers". Deployments, patching, policies and permissions all target groups, so most work starts here.

## Before you start

- Reading groups needs **See the fleet**. Creating and changing them needs **Manage computer groups** (`groups.manage`).

## Two kinds of group

| Kind | Membership | Use it for |
| --- | --- | --- |
| **Dynamic** | Every endpoint that matches its rules, re-evaluated as inventory changes | Almost everything: "Windows servers", "anything running nginx", "laptops in the Paris site" |
| **Static** | A fixed list of endpoints you choose | A pilot ring, or a handful of machines with nothing in common |

A dynamic group stays correct by itself: a new laptop that matches the rules joins the moment it reports, and one that stops matching leaves.

## Create a dynamic group

1. Open **Administration → Computer Groups**.
2. Under **New computer group**, enter a **Name** and a **Description** that says who is in it.
3. Leave **Type** on **Dynamic — matched by rules**.
4. Choose **+ Add rule** and build a rule from a field, a comparison and a value. For example:
   - **Operating system** equals `windows`
   - **Installed application name** contains `Chrome`
   - **Computer OU** ends with `OU=Laptops,DC=example,DC=com`
5. Add more rules, and choose whether an endpoint must match **all** of them or **any** of them.
6. Check **Preview**: it lists the endpoints the rules match right now.
7. Choose **Save group**.

> **Tip:** list fields such as installed applications or directory groups match on any item. `equals Finance` means "one of them is Finance"; `not equals Finance` means "none of them is".

## Create a static group

1. Set **Type** to **Static — a fixed list of devices**.
2. Pick the endpoints from the list.
3. Choose **Save group**.

## Change or delete a group

Choose **edit** or **delete** next to the group. Before deleting, check what targets it: a deployment, patch schedule or policy whose group is deleted stops rather than spreading to the whole fleet, and shows the group as deleted until you choose another.

## Check it worked

- The group's row shows how many endpoints it holds.
- Anywhere you choose targets (Deploy, Patch, Playbooks, Enforce), the group appears in the target list.
