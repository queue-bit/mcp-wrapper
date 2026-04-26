# MCP Security Wrapper — Use Case & Positioning
*Compared to AWS AgentCore and similar managed platforms*

---

## Contents

- [What problem does this solve?](#what-problem-does-this-solve)
- [Who is this for?](#who-is-this-for)
- [Comparison with AWS AgentCore](#comparison-with-aws-agentcore)
- [DLP implementation options](#dlp-implementation-options)
- [Are they mutually exclusive?](#are-they-mutually-exclusive)
- [What this tool explicitly does not do](#what-this-tool-explicitly-does-not-do)

---

## What problem does this solve?

Model Context Protocol (MCP) standardizes how LLM agents communicate with external tools and services. What it does not standardize is *who is allowed to call what*, *where credentials live*, or *what happened after the fact*.

Without a security layer, connecting an LLM agent to real services means:

- The agent process has direct access to credentials for every service it can reach
- A successful prompt injection can cause the agent to call any tool the MCP server exposes — there is no enforcement boundary short of the server itself
- Sensitive data can leave your environment silently through a whitelisted, credentialed tool call — and you may not know until after the fact
- There is no structured record of what the agent did, when, and why

This wrapper addresses those gaps by sitting between the agent and its MCP servers, enforcing rules before calls are made and logging everything regardless of outcome.

---

## Who is this for?

**Home and small-team deployments** where agents have access to real services — home automation, email, calendars, file storage — and the operator wants meaningful control without standing up cloud infrastructure.

**Security-conscious teams** running agents in environments where:
- Tool calls need human approval before execution
- Outbound data needs to be inspected before it reaches third-party services
- Per-agent permission scoping matters (different agents should have different access)
- Audit logs need to stay on-premises or in a specific location

**Multi-cloud or hybrid environments** where agents interact with services across AWS, GCP, on-prem infrastructure, or consumer APIs that have no native access control layer.

**Operators who want vendor independence** — the wrapper works with any MCP-compatible client and any MCP server without modification to either.

---

## Comparison with AWS AgentCore

AWS AgentCore is Amazon's managed platform for deploying and running AI agents within the AWS ecosystem. It is a well-engineered product for teams running agents on AWS. This section is an honest comparison, not a dismissal.

### Where AgentCore and this wrapper overlap

Both provide:
- Authentication for agent-to-tool connections
- Access control over which tools an agent can call
- Audit logging of agent activity
- Credential management (AgentCore via IAM/Secrets Manager; this wrapper via Vault, env, or keyring)

### Where this wrapper goes further

**Parameter-level enforcement**

AgentCore access control operates at the tool level, backed by IAM. This wrapper supports rules down to individual parameters — restricting which values a tool can be called with, enforcing regex patterns, and maintaining explicit allowlists. A tool that is permitted can still be blocked if the parameters don't match the rules.

```toml
[[agents.personal-assistant.rules]]
tool = "gmail.send"
confirmation_required = true
allowed_params.to.allowlist = ["known@example.com"]
# gmail.send is allowed, but only to this address
```

**DLP scanning on outbound parameters**

Before a tool call leaves the wrapper toward any MCP server, the DLP scanner inspects the parameters for sensitive data patterns — credentials, PII, internal IP ranges, API keys. It can block the call, redact the matched content, or log a violation and allow through. The same inspection runs on MCP server *responses* before they reach the agent, catching sensitive data in inbound content and injected instructions embedded in external data.

This matters most for cloud-hosted MCP servers (web search, email, document storage) where the wrapper has no visibility into what the server does with received data. A prompt injection that causes an agent to embed a local credential in a web search query will be caught before it leaves.

AgentCore does not have an equivalent outbound DLP capability. See the [DLP options section](#dlp-implementation-options) below for implementation detail.

**Human confirmation gate**

Individual tool calls can be flagged as requiring human approval before execution. The agent receives a pending status; execution is held until an out-of-band approval is received. Unresponded requests auto-deny after a configurable timeout.

This is particularly valuable for high-impact or irreversible actions: sending email, modifying home automation state, deleting files. AgentCore has no equivalent pause-and-approve mechanism at the individual tool call level.

**Non-AWS MCP servers**

AgentCore is designed for agents and tools running within the AWS ecosystem. This wrapper is protocol-level — it proxies any MCP server, regardless of where it runs: a local Home Assistant instance, a self-hosted service, a Google API, or an AWS-hosted service. There is no requirement that the downstream services have any relationship with AWS.

**Local and on-premises deployment**

The wrapper runs on any machine that can run Python — a Raspberry Pi, a home server, a VM, a container. No AWS account is required. Audit logs are written to local SQLite or JSONL files and stay where you put them. There is no dependency on cloud infrastructure for the security layer itself.

**Per-agent permission profiles with fine-grained scoping**

Each agent authenticates with the wrapper and receives a permission profile that specifies exactly which MCP servers it can reach and which tools it can call. Two agents can connect to the same wrapper instance with completely different scopes. Adding a new MCP server to the wrapper makes it available for assignment — it does not automatically grant any agent access to it.

AgentCore uses IAM for access control, which is powerful but infrastructure-scoped. It is not designed for the pattern of multiple logical agents with different tool-level permission profiles connecting to a shared proxy.

### Where AgentCore is stronger

**Managed infrastructure**

AgentCore is a fully managed service. There is no server to run, no process to keep alive, no SQLite file to back up. It scales automatically and carries AWS's reliability and availability guarantees.

**AWS ecosystem integration**

If your agents, tools, and data are already in AWS, AgentCore integrates naturally with IAM, CloudTrail, CloudWatch, Lambda, Bedrock, and the rest of the stack. This wrapper has no equivalent native integration with AWS services — it treats them as external MCP servers like any other.

**Compliance certifications**

AWS services carry SOC 2, HIPAA, FedRAMP, and other certifications by default. For regulated environments where these certifications are a requirement, AgentCore is the appropriate choice. This wrapper has no certifications.

**Production scale**

For high-volume production deployments, a managed service is likely the right operational choice. This wrapper is designed for home, small-team, and security research use cases — not for handling thousands of concurrent agent sessions.

### Summary table

| Capability | MCP Security Wrapper | AWS AgentCore |
|---|---|---|
| Tool-level access control | Yes | Yes |
| Parameter-level whitelist rules | Yes | No |
| DLP scanning on outbound parameters | Yes | No |
| Human confirmation gate per tool call | Yes | No |
| Per-agent permission profiles | Yes | Partial (IAM) |
| Non-AWS MCP servers | Yes | No |
| Local / on-premises deployment | Yes | No |
| Audit log ownership and location | Operator-controlled | CloudTrail / CloudWatch |
| Vendor independence | Yes | No — AWS-native |
| Managed infrastructure | No — self-hosted | Yes |
| AWS ecosystem integration | No | Yes |
| Compliance certifications | No | Yes (SOC2, HIPAA, etc.) |
| Production scale | Limited | Yes |

---

## DLP Implementation Options

The DLP scanner is a layered pipeline. Layers run in order; a block from any layer stops the call. Each layer is independently enabled — operators pay only the latency cost of what they turn on.

### What DLP covers in this wrapper

Two inspection points exist in the call path:

- **Outbound** — tool call parameters, inspected after whitelist approval and before the credential broker dispatches the call. The last point where data can be stopped before it leaves.
- **Inbound** — MCP server responses, inspected before the content reaches the agent. The primary vector for indirect prompt injection via external data.

### Layer 1 — Regex (built-in, always available)

Pattern matching against known secret and sensitive data formats. Pattern sets are drawn from the [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) rule libraries, which are maintained as new credential formats emerge. Covers: API keys, bearer tokens, private keys, AWS/GCP/Azure credentials, database connection strings, and internal IP ranges.

Near-zero latency overhead. No additional dependencies. Catches the highest-confidence cases.

### Layer 2 — PII detection via Microsoft Presidio (optional, local)

[Presidio](https://github.com/microsoft/presidio) is an open-source PII detection and anonymization library that runs entirely on your own hardware. It combines regex with spaCy NLP models to detect names, emails, phone numbers, credit card numbers, SSNs, IBANs, passport numbers, medical identifiers, and more. Its built-in anonymizer maps directly to the `redact` action.

Install: `pip install mcp-wrapper[dlp-pii]`

Requires spaCy language models (100–500MB depending on language). Adds per-call latency — recommended to scope to MCP servers that handle sensitive data (email, documents) rather than enable globally.

**Why not a cloud DLP API?** AWS Comprehend, Google Cloud DLP, and Azure Cognitive Services are all capable products. They are not appropriate here. Sending data to a cloud DLP service to determine whether it is safe to send to a cloud MCP server is circular — the data has already left your environment by the time you receive the verdict. Cloud DLP APIs are only appropriate in fully managed deployments where the DLP service is in the same trust boundary as the MCP server.

### Layer 3 — Prompt injection detection via llm-guard (optional, local)

[llm-guard](https://github.com/protectai/llm-guard) provides scanners specifically for prompt injection, jailbreaking, and toxic content in both inputs and outputs. In this pipeline, it is most useful on the inbound side — inspecting MCP server responses before they reach the agent to detect injected instructions embedded in external data (web pages, emails, documents).

Install: `pip install mcp-wrapper[dlp-injection]`

Runs locally. Latency scales with content length. [Lakera Guard](https://lakera.ai) is a cloud API alternative with higher accuracy at the cost of response content leaving your environment.

### Choosing layers by deployment

| Deployment | Regex | Presidio | llm-guard |
|---|---|---|---|
| Home / local-only MCP servers | Yes | No | No |
| Home with cloud MCP servers (Gmail, web search) | Yes | Yes (scoped to cloud servers) | Optional |
| Small team, mixed on-prem and cloud | Yes | Yes | Yes |
| Security research / high-trust required | Yes | Yes | Yes |

---

## Are they mutually exclusive?

No. The two tools operate at different layers and can coexist.

A team running agents on AWS Bedrock through AgentCore could still deploy this wrapper in front of non-AWS MCP servers (Home Assistant, Gmail, on-prem APIs) that AgentCore cannot reach. AgentCore handles the AWS-native tooling; this wrapper handles everything else.

Similarly, an operator who wants DLP scanning or human confirmation on specific high-risk tool calls could run this wrapper even for AWS-hosted MCP servers, adding a policy enforcement layer that AgentCore does not provide.

---

## What this tool explicitly does not do

- It is not a general-purpose API gateway
- It does not manage MCP server deployment or lifecycle
- It does not make LLMs prompt-injection-proof — it limits the damage a successful injection can cause
- It does not provide network segmentation — use VLANs, firewall rules, or Tailscale for that
- It does not replace a VPN or TLS — transport security is a complementary control
- It does not carry compliance certifications
