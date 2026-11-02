# Accounts, roles and sign-in
<!-- group: Start here; order: 3; pages: /admin -->

Give colleagues an account, decide what each of them may see and do, connect single sign-on, and protect sign-in with a second step.

## Before you start

- You need **Manage users and roles** (`users.manage`) to create accounts and roles. Identity providers and the SSO allowlist also need **Manage sign-in** (`identity.manage`).

## How access works

- An **account** signs in, either with a local password or through single sign-on (SSO).
- A **role** is a named set of permissions. An account gets permissions from the roles given to it directly and from the roles of any group it belongs to.
- **An account with no role sees nothing** but its own preferences and Help. Give it a role before expecting it to work.
- Two roles are built in:
  - **admin** holds every permission.
  - **user** holds **See the fleet** and **Read the audit log**: it sees everything and changes nothing.

| Permission | What it allows |
| --- | --- |
| See the fleet (`fleet.read`) | Endpoints, inventory, findings, deployments and reports; read-only questions to endpoints. Almost every page needs it. |
| Read the audit log (`audit.read`) | Who did what, to which endpoint, from where. |
| Deploy software and run actions (`deploy.manage`) | Packages, scripts, custom sensors, Direct Connect: anything that runs code on endpoints. |
| Manage patches (`patches.manage`) | Approve, schedule and deploy patches; run compliance and vulnerability scans. |
| Manage computer groups (`groups.manage`) | Create and edit the groups deployments target. |
| Manage settings (`settings.manage`) | Server configuration and API tokens. |
| Manage users and roles (`users.manage`) | Accounts, groups and roles. |

The full list, with a description of each, is in the role editor.

## Add an account

1. Open **Administration** in the rail and choose **Users**.
2. Under **Add local user**, enter a **Username**, a temporary **Password** of at least 12 characters, and optionally a display name. Choose **Add user**.
3. In the users list, choose the new account and add a role, for example **user**.
4. Send the username and password to the person through a channel you trust, and ask them to change the password and set up two-step sign-in.

## Create a role

1. **Administration → Roles**.
2. Under **Create role**, name it after the job, for example "Help desk".
3. Tick the permissions it needs. Start with **See the fleet**; add only what the job requires.
4. Choose **Create role**, then give the role to accounts or groups under **Users** or **Groups**.

> **Tip:** to let a role act on only part of the fleet, or reach only some modules, use **Access** (action groups and content sets). See [Access control](access.md).

## Connect single sign-on

1. **Administration → Single Sign-On**. Under **Add an identity provider**, enter the provider's issuer URL, client ID and client secret (from your identity provider's app registration), and choose **Save provider**.
2. Copy the **Redirect URI** shown in the form into your identity provider's app registration.
3. Under **SSO allowlist**, add a rule for who may sign in, for example your company's email domain, and choose **Save allowlist**. **With no rule, nobody can sign in through SSO.**
4. Give SSO accounts roles, or map identity-provider groups to mustra groups that hold roles.

A person allowed by the allowlist gets an account the first time they sign in. Until it has a role (directly, or through a group), they see the "no access yet" page.

## Two-step sign-in

For local accounts, mustra asks for a code from an authenticator app after the password.

**Set it up for yourself**

1. Select **Preferences** (the cog at the bottom of the rail) and find **Two-step sign-in**.
2. Choose **Set up**, scan the QR code with an authenticator app (or type the key), and enter the code it shows.
3. Save the **recovery codes** somewhere safe. Each works once, in place of a code, if you lose your phone.

**Require it for everyone**

1. **Administration → Break-glass Account**, section **Two-step sign-in**.
2. Turn on the requirement. Every local account that has not set it up is asked to at its next sign-in.

**Someone lost their phone and their recovery codes**

An administrator opens **Administration → Users**, chooses the account and resets its two-step sign-in. The person sets it up again at the next sign-in.

SSO accounts use their identity provider's own second factor.

## Sessions

A session ends after 12 hours, or after an hour without activity, whichever comes first.

## Check it worked

- Sign in as the new account in a private browser window. With a role, the rail shows the modules that role may open; without one, you see "Your account has no access yet".
- **Administration → Audit Log** records every account, role and sign-in change.
