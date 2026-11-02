# Impact analysis
<!-- group: Secure; order: 47; pages: /impact -->

If an account, group or endpoint were compromised, what else could an attacker reach? Impact maps it from your Active Directory and from who is administrator and signed in on each endpoint.

## Before you start

- Reading Impact needs **See the fleet**.
- Connect your directory: **Administration → Directory** (Active Directory over LDAP, with a read-only account). Without it, Impact still uses each endpoint's local administrators and signed-in users.

## Read it

- **Overview**: the users and groups with the most reach, the endpoints that reach the most, and **What to fix first**.
- **Findings**: shapes worth fixing, such as a privileged account signed in to an ordinary workstation, a group that administers most of the fleet, or a disabled account that still holds rights.
- **Users**, **Groups** and **Endpoints**: every object, rated by what it can reach. Open one to see why.
- **Paths**: choose a starting point and a target and **Find path** to see the shortest chain an attacker could follow, hop by hop.

## Act on it

The usual fixes are outside mustra: remove an account from a group, stop administrators signing in to workstations, give a service its own account. Impact recalculates as directory and endpoint data change, so a fix shows within the next collection.

Setting an endpoint's criticality (under **Performance → Risk Score**) makes paths to it weigh more.
