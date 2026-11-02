# Security Policy

## Supported versions

Only the latest published version receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report vulnerabilities privately by emailing the repository
maintainers or using GitHub's private security advisory feature:
<https://github.com/bnomei/towershield/security/advisories/new>

Include:

- A description of the vulnerability.
- Steps to reproduce or a proof-of-concept (if safe to share).
- Affected versions.
- Any suggested fix.

We aim to acknowledge reports within 72 hours and publish a fix or advisory
within 30 days.

## Scope

This library is a path-denylist middleware. Please report:

- Bypass techniques that allow a matched scanner path to reach the inner
  service.
- Incorrect percent-encoding behaviour that enables a bypass.
- Unsafe code introduced by a dependency.

Out of scope:

- False positives (paths incorrectly blocked) – these are bugs, not security
  vulnerabilities; please open a regular issue.
- Requests for new rules – please open a regular issue or pull request.

## Rule evidence and review

Last research review: **2026-11-02**. Rules reduce recognizable probes; they
do not establish that a deployment is vulnerable or fully mitigate a CVE.
Credential paths below are documented storage locations, not claims of
observed exploitation of every tool. Custom storage locations remain outside
these filename rules.

Evidence for the additions from this review:

| Rules / files | Source and rationale |
| --- | --- |
| Cargo `.cargo/credentials` and `.cargo/credentials.toml` | [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html): registry token storage, including the legacy filename. |
| uv `.local/share/uv/credentials/credentials.toml` | [uv HTTP authentication](https://github.com/astral-sh/uv/blob/main/docs/concepts/authentication/http.md): default Unix plaintext credential store. |
| Poetry `.config/pypoetry/auth.toml` | [Poetry repositories](https://python-poetry.org/docs/repositories/) and [project location discussion](https://github.com/python-poetry/poetry/issues/3216): plaintext fallback when a keyring is unavailable. |
| GitHub CLI `.config/gh/hosts.yml` | [CLI authentication](https://cli.github.com/manual/gh_auth_login) and [project path evidence](https://github.com/cli/cli/issues/7757): plaintext token fallback. |
| GitLab Runner `.gitlab-runner/config.toml` and `etc/gitlab-runner/config.toml` | [Runner configuration](https://docs.gitlab.com/runner/configuration/advanced-configuration/): user/system locations, authentication tokens and cache credentials. |
| Terraform `.terraform.d/credentials.tfrc.json` | [HashiCorp login tutorial](https://developer.hashicorp.com/terraform/tutorials/cloud/cloud-state-api): plaintext API token storage. |
| Kubernetes `.kube/config` | [Kubernetes cluster access](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/): authentication material or references; not every kubeconfig embeds a secret. |
| `application_default_credentials.json` | [Google ADC documentation](https://docs.cloud.google.com/docs/authentication/application-default-credentials): catch copied files as well as canonical gcloud directories. |
| Gemini `.gemini/oauth_creds.json`, `mcp-oauth-tokens.json`, `settings.json` | [Storage source](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/config/storage.ts) and [configuration](https://geminicli.com/docs/reference/configuration): tokens and potentially secret-bearing MCP headers/environment. Directory-qualified suffixes also cover `.cache/.gemini/`. |
| Windsurf `.codeium/windsurf/mcp_config.json` | [Client integration documentation](https://docs.ionos.com/cloud/ai/mcp-server/connect-to-an-ai-client/windsurf): MCP configuration with credentials. |
| `smtp_keys.json`, `smtp_tokens.json` | [SANS ISC, 2025-03-04](https://isc.sans.edu/diary/31736): observed probes on March 1–2, 2025. |
| `.DS_Store` | [SANS ISC, 2022](https://isc.sans.edu/diary/28910): directory reconnaissance; older evidence, not a new exploit. |
| `.user.ini` | [PHP per-directory configuration](https://www.php.net/manual/en/configuration.file.per-user.php): private runtime configuration, not a generic `.ini` ban. |
| `eval-stdin.php` | [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), CVE-2017-9841; [F5, 2026-03-12](https://www.f5.com/labs/articles/looking-at-the-smartermail-api-vulnerability-cve-2026-24423) reports continued PHPUnit exploitation attempts in February 2026. |
| `/_ignition/execute-solution` | [Qualys, 2025-10-30](https://blog.qualys.com/vulnerabilities-threat-research/2025/10/30/what-security-teams-need-to-know-as-php-and-iot-exploits-surge): observed Laravel Ignition exploit attempts, CVE-2021-3129. |
| `/__nextjs_original-stack-frames` | [Next.js v15.3.0 source](https://github.com/vercel/next.js/blob/v15.3.0/packages/next/src/client/components/react-dev-overlay/utils/stack-frame.ts): plural batched development endpoint, distinct from the existing singular path; no standalone CVE mitigation claim. |

### Deployment-specific candidates, not defaults

Recent exploitation also targets legitimate product functions:

- SAP `/developmentserver/metadatauploader`, CVE-2025-31324:
  [Rapid7, 2025-04-28](https://www.rapid7.com/blog/post/2025/04/28/etr-active-exploitation-of-sap-netweaver-visual-composer-cve-2025-31324/).
- SharePoint `/_layouts/15/ToolPane.aspx`, ToolShell CVE family:
  [Microsoft, 2025-07-22](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/).
- SmarterMail `/api/v1/settings/sysadmin/connect-to-hub`, CVE-2026-24423:
  [F5, 2026-03-12](https://www.f5.com/labs/articles/looking-at-the-smartermail-api-vulnerability-cve-2026-24423).

Use application-specific rules only after reviewing the functionality they
disable and confirming requests pass through the enforcement point. Patch the
affected product. Do not blanket-deny `/api`, `/admin`, archives, or SQL downloads
to compensate for vulnerabilities in legitimate routes.

### Repeatable review process

Before a rule release, and after relevant vendor advisories or scanner reports:

1. Review the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
   vendor advisories, and observed-probe reports such as SANS ISC. Record source
   and observation dates separately; attempted exploitation is not confirmed compromise.
2. Verify the actual path in primary documentation, source, or telemetry. Check
   existing coverage before adding a rule. Prefer exact or slash-bounded suffix
   rules over generic names or broad prefixes.
3. Add blocked examples and nearby legitimate counterexamples to the path
   fixture. Validate default, no-default-features, and all-features builds, plus
   Cloudflare export budgets and diagnostics. Keep public discovery reachable.
4. Review normalization boundaries and allow exclusions at every enforcement
   point. Tower exclusions are not exported to Cloudflare; export warnings must
   be resolved before deployment.

This is a maintainer workflow, not a scheduled monitor or runtime feed. Rules
remain reviewed, versioned data with no network calls or automatic downloads.
