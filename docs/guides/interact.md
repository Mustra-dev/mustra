# Ask questions of your fleet
<!-- group: See your fleet; order: 20; pages: /interact -->

Interact answers questions like "which machines have Chrome older than version 120" or "who is signed in on the finance laptops", across every endpoint, in seconds, and lets you act on the answer.

## Before you start

- Asking questions needs **See the fleet**. Acting on the answer (deploying, patching) needs the permission for that action.

## How questions are answered

Most questions are answered from the **inventory** mustra already holds: what each endpoint last reported. That is instant and includes endpoints that are offline. Each answer shows how old the data behind it is.

When you need what is true right now, use a **live query** from an endpoint's page (processes, services, network connections). It asks the endpoint directly and only online endpoints answer.

## Ask a question

1. Open **Interact** (or use the **Query** box on Home, or the question icon in the search bar).
2. Type a question. It reads `get <fields> from all machines`, optionally followed by `with <field> <comparison> <value>`:
   - `get hostname and os from all machines`
   - `get installed_apps.name and installed_apps.version from all machines with installed_apps.name contains Chrome`
   - `get hostname from all machines with patches.count greater_than 5`
3. Choose **Run**.

Comparisons are `equals`, `not_equals`, `contains`, `starts_with`, `ends_with`, `greater_than`, `less_than`, `exists` and others; the builder lists them all. If you are not sure what to type, choose **Build query**. It is a form: pick the fields to **get**, then add **where** conditions, and it writes the question for you.

## Read the answer

- Each row is one distinct answer, with the number of endpoints that gave it. Select a row to see those endpoints.
- **Drill down into these endpoints** asks a follow-up question of just the endpoints you selected.
- **Export CSV** downloads the answer.

## Act on the answer

Select rows, then:

- **Deploy action…** runs a package or action on those endpoints. See [Deploy software](deploy-software.md).
- **Apply patches…** patches them. See [Patch endpoints](patching.md).

The action runs on the endpoints behind the rows you selected, not on whatever matches the question later.

## Save a question

1. After running it, choose **Save this query**, and give it a name and description.
2. Find it under **Saved Queries**: **run** it again, **open in builder** to change it, or **delete** it.
3. A saved question can feed a dashboard panel or a report.

**Query History** keeps the questions you ran recently.

## If something goes wrong

- **A field returns nothing:** the sensor behind it may not run on that operating system, or has not reported yet. **Sensors → Fleet Coverage** shows which endpoints report each sensor and how fresh it is.
- **The count seems low:** offline endpoints answer from their last report; endpoints that have never reported a sensor cannot answer about it.
