# Agent protocol compatibility

TowerShield is compatible with agent-ready sites by default. Its built-in
rules target private configuration files and scanner probes; they do not add a
blanket deny or allow rule for agent discovery, authentication, commerce, or
content-negotiation endpoints.

This distinction matters. `/.mcp.json` is commonly a private local MCP client
configuration and is blocked, while `/.well-known/mcp.json` is an intentionally
public discovery document and remains allowed. Similarly, TowerShield does not
blanket-allow `/.well-known/**`: a misplaced secret such as
`/.well-known/.env` is still blocked by the default regex tier.

Terminology used below:

- **MCP** is the Model Context Protocol. “MPC” in this context is usually a
  transposition.
- **OIDC** is OpenID Connect. “OCID” usually refers to OIDC here.
- **MCP Apps** is an optional UI extension to MCP. A normal MCP server does not
  need a UI.

## Public compatibility surface

The following resources are intentionally left reachable by the built-in rule
set. Applications only need to publish the entries relevant to their own
capabilities.

| Area | Public mechanism or example path | Status and TowerShield boundary |
| --- | --- | --- |
| Crawl policy | `/robots.txt`, `/sitemap.xml` | The Robots Exclusion Protocol is standardized by [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309). AI crawler rules and Content Signals live inside `robots.txt`; they are declarations for cooperating bots, not access control, and TowerShield does not interpret them. |
| Agent-readable content | `/llms.txt`, `/llms-full.txt`, or `Accept: text/markdown` | These are public content surfaces. Header-based content negotiation is outside a path denylist. |
| HTTP discovery links | `Link` response headers | Links can advertise alternate representations and protocol resources without a dedicated path. TowerShield does not inspect response headers. |
| DNS discovery | DNS-AID and `_mcp` DNS records | DNS discovery has no HTTP request path and therefore sits completely outside TowerShield. |
| Web Bot Auth | `/.well-known/http-message-signatures-directory` | The key directory is public; request authentication uses HTTP message-signature headers. Web Bot Auth remains an [IETF work item](https://datatracker.ietf.org/wg/webbotauth/about/). It identifies a bot operator but does not authorize access on behalf of an end user, and TowerShield does not verify its signatures. |
| API Catalog | `/.well-known/api-catalog` | Standardized by [RFC 9727](https://www.rfc-editor.org/rfc/rfc9727) as a public catalog of APIs and their documentation. |
| OAuth authorization server | `/.well-known/oauth-authorization-server` | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) metadata is public. Issuers with path components can produce additional suffix paths. |
| OpenID Connect | `/.well-known/openid-configuration` | [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) is public and can coexist with RFC 8414 metadata. |
| OAuth protected resource | `/.well-known/oauth-protected-resource` and path-qualified variants such as `/.well-known/oauth-protected-resource/mcp` | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) metadata tells a client which authorization server protects a resource. A `401` response can advertise its URL through `WWW-Authenticate`. |
| Agent registration | `/auth.md` | [auth.md](https://github.com/workos/auth.md) is an emerging, Markdown-based agent-registration guide layered on OAuth discovery; it is not an OAuth or OIDC standard. |
| MCP endpoint | `/mcp` or another application-selected path | Core MCP tools and resources work without a UI. Remote protected MCP servers use RFC 9728 and OAuth discovery according to the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization). |
| MCP discovery | `/.well-known/mcp.json`, `/.well-known/mcp`, or the draft `/.well-known/mcp/server-card.json` | MCP server-card discovery is still evolving. The [MCP Server Card working group](https://modelcontextprotocol.io/community/working-groups/server-card) tracks the proposal, so applications should not assume one path is universally supported yet. |
| MCP Apps | MCP `ui://` resources referenced by tool metadata | [MCP Apps](https://modelcontextprotocol.io/extensions/apps/overview) is an optional interactive-UI extension. Headless tools continue to return text, structured data, images, or ordinary resources. Its sandbox, CSP, permissions, and user-consent model are host concerns rather than path matching. |
| Agent Skills | `/.well-known/agent-skills/index.json` and linked `SKILL.md` files | The skill file format has a published [Agent Skills specification](https://agentskills.io/specification); web discovery is a separate [Cloudflare proposal](https://github.com/cloudflare/agent-skills-discovery-rfc). |
| A2A Agent Card | `/.well-known/agent-card.json` | The [A2A specification](https://a2a-protocol.org/latest/specification/) uses a public agent card to advertise capabilities and authentication requirements. |
| WebMCP | Tools registered through `document.modelContext` or declarative HTML forms | [WebMCP](https://developer.chrome.com/docs/ai/webmcp) is an experimental browser API, not an HTTP discovery endpoint. It currently requires a browsing context and applies origin-isolation and permissions-policy controls. |
| MPP discovery | `/openapi.json` with `x-payment-info` | The [Machine Payments Protocol](https://mpp.dev/advanced/discovery) treats OpenAPI discovery as advisory; the runtime HTTP `402` challenge is authoritative. |
| UCP discovery | `/.well-known/ucp` | The [Universal Commerce Protocol](https://ucp.dev/latest/specification/overview/) publishes a public business profile containing services, transports, capabilities, and signing keys. |
| ACP discovery | `/.well-known/acp.json` | The [Agentic Commerce Protocol discovery proposal](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/blob/main/rfcs/rfc.discovery.md) defines a public, seller-scoped capability document. It excludes secrets, merchant enumeration, payment-provider routing, and transaction-specific data. |

## Header- and payload-level protocols

Several readiness checks cannot be implemented or secured by TowerShield
because the middleware deliberately inspects only request paths:

- **Content Signals** are `Content-Signal` directives in `robots.txt`.
- **Web Bot Auth** uses `Signature-Agent`, `Signature-Input`, and `Signature`
  request headers plus a public key directory.
- **OAuth/OIDC** requires TLS, issuer validation, redirects, token validation,
  scopes, PKCE where applicable, and safe client registration. TowerShield does
  not authenticate users or agents.
- **x402** uses HTTP `402` and, in version 2, `PAYMENT-REQUIRED`,
  `PAYMENT-SIGNATURE`, and `PAYMENT-RESPONSE` headers. Its
  [specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
  requires payment authorization and replay protections.
- **MPP** also uses HTTP `402`, with challenges, credentials, and receipts
  carried by its transport. Discovery cannot override the live challenge.
- **UCP and ACP** define commerce operations beyond their public discovery
  documents. Authentication, payment authorization, idempotency, inventory,
  checkout state, and consent remain application responsibilities.

Do not put credentials, client secrets, bearer tokens, private signing keys,
merchant-specific routing, or customer information in any public discovery
document. Validate every discovered URL and issuer before following it, and
apply ordinary rate limits and caching to public metadata endpoints.

## Maintaining compatibility

The default-rule fixture and unit tests contain representative discovery,
authentication, and commerce paths. New built-in deny rules must keep those
paths allowed unless a future protocol explicitly makes one private.

The tests intentionally assert outcomes rather than install built-in allow
rules. This preserves application control: a custom rule can still deny an
unused protocol endpoint, and suspicious files beneath `/.well-known/` do not
receive a universal bypass.
