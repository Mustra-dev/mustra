# Getting started
<!-- group: Start here; order: 1; pages: / -->

Sign in, add your first endpoints and find your way around the console. Read this first; every other guide assumes you have done it.

## Before you start

- A running mustra server. If you are installing one, follow [Install the server](install-server.md) first.
- An administrator account. The first one is created from the one-time setup link the server prints in its log the first time it starts.

## 1. Sign in

1. Open the console in a browser, at the address your administrator gave you.
2. Enter your **Username** and **Password** and choose **Sign in**. If your organisation uses single sign-on, choose the identity provider's button instead.
3. If two-step sign-in is on, enter the six-digit code from your authenticator app.

> **Tip:** set up two-step sign-in for yourself under **Preferences** (the cog at the bottom of the left rail). See [Accounts, roles and sign-in](users-and-access.md).

## 2. Add your first endpoint

An endpoint is any computer the mustra agent runs on: a laptop, a desktop or a server, on Windows, macOS or Linux.

1. In the left rail, open **Modules** and choose **Client Management**, then **Manual Install**.
2. Give the token a **Label** (for example "First laptops"), set **Uses** to the number of machines you will install now, and choose **Create enrollment token**.
3. Copy the command for the endpoint's operating system:
   - **Linux and macOS:** paste it into a terminal on the endpoint. It asks for your password because the agent installs as root.
   - **Windows:** open PowerShell **as administrator** and paste it.
4. Within a minute the endpoint appears on **Home** under **Online endpoints**.

The token is shown only once. If you lose it, create another and revoke the old one. [Install agents](install-agents.md) covers macOS permissions, pushing to many machines at once and removing the agent.

## 3. Look around

- **Home** shows how many endpoints are online, what they run and what needs attention. The tiles are links: select one to see the endpoints behind the number.
- **The search box** at the top finds an endpoint by hostname, operating system, site or IP address. Select a result to open that endpoint's page, which has everything mustra knows about it.
- **The left rail** groups the modules: **Modules** (everything you work in), **Reporting**, **Shared Services**, **Administration** and **Tools**. Hover or select an icon to see what is inside.
- **The bell** shows notifications for you; **the triangle** opens Guide, the list of things that need attention across the fleet.
- **Help** (the question mark at the bottom of the rail) brings you back here. Most pages also have a **Guide** link at the top right that opens the guide for that page.

## 4. Ask your first question

1. On **Home**, type a question into **Query**, for example `get hostname and os from all machines`, and choose **Run**.
2. The answer comes from the inventory mustra already holds, so it is instant and includes endpoints that are offline.
3. Choose **Build query** for a form that writes the question for you.

[Ask questions of your fleet](interact.md) explains questions, live queries and saving them.

## What to do next

| If you want to… | Read |
| --- | --- |
| Let colleagues in, with the right access | [Accounts, roles and sign-in](users-and-access.md) |
| Install software or run a script on endpoints | [Deploy software](deploy-software.md) |
| Keep operating systems patched | [Patch endpoints](patching.md) |
| See which endpoints are vulnerable | [Vulnerabilities and risk](vulnerabilities.md) |
| Check endpoints against a security baseline | [Compliance](compliance.md) |
