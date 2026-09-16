---
name: jira-task-lifecycle
description: Enforce the mandatory Jira task intake workflow - search project HUN for existing tickets, detect collisions/duplicates, create missing tickets, and gate implementation on explicit user approval.
---

# Jira Task Lifecycle & Gated Execution

This skill defines the standardized protocol for handling any task presented by the user.

## Pre-Requisites & Project Context
- **Jira Project Key**: `HUN` (Hunter)
- **MCP Server**: `jira`
- **Available Tools**:
  - `call_mcp_tool` with `ServerName: "jira"`:
    - `jira_search` (actions: `issues`, `projects`, `create_metadata`)
    - `jira_issues` (actions: `get`, `create`, `update`, `assign`)
    - `jira_comments`, `jira_links`, `jira_workflow`

---

## Workflow Steps

### Step 1: Search & Collision Discovery
Before writing any code or modifying files, search Jira for tickets related to the prompt:
1. Construct a targeted JQL query:
   ```json
   {
     "action": "issues",
     "jql": "project = HUN AND (summary ~ \"<keywords>\" OR description ~ \"<keywords>\") ORDER BY updated DESC"
   }
   ```
2. Evaluate results for:
   - **Direct Duplicate**: An identical issue already logged.
   - **Collision / Overlap**: An existing open ticket that touches the same component, service, or functionality.
   - **Prerequisite / Dependency**: An issue that must be addressed first.

### Step 2: Create Missing Ticket (If Not Present)
If no existing ticket matches the task:
1. Formulate a concise summary and structured description.
2. Call `jira_issues` with action `create`:
   ```json
   {
     "action": "create",
     "projectKey": "HUN",
     "issueType": "Task",
     "summary": "<Clear, actionable title>",
     "description": "<Context, requirements, and acceptance criteria>"
   }
   ```
3. Record the generated Issue Key (e.g., `HUN-16`).

### Step 3: Present Findings & Wait for User Instruction (Gate)
Present a concise summary to the user:
- **Jira Issue**: Key and title (e.g., `[HUN-16] Implement XYZ`).
- **Collision Check**: State whether any related or colliding tickets were found.
- **Proposed Plan**: Outline the high-level implementation plan.
- **Gate**: Explicitly state that you are standing by for approval before proceeding.

> **DO NOT** edit codebase files, execute builds, or modify infrastructure until the user explicitly says "proceed", "work on it", or "go ahead".

### Step 4: Authorized Execution & Resolution
Once the user authorizes work:
1. Implement the solution according to workspace invariants (`AGENTS.md`).
2. Run relevant tests and verify.
3. Include the Jira key in commit messages (e.g., `feat(subsystem): <summary> (HUN-16)`).
4. Update or comment on the ticket if appropriate using `jira_comments`.
