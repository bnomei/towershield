//! Conservative built-in scanner-probe denylist shipped with the library.
//!
//! Rules are plain [`Rule`] values built with the same public API applications
//! use. Nothing is special-cased inside the matcher; disable or override via
//! [`Rule::enabled`], allow rules, or a custom [`RuleSet`].
//!
//! # Versioning policy
//!
//! Built-in content follows crate semver: **adding** a rule is a minor bump
//! (more paths may block); **removing** or weakening a match is a major bump.
//!
//! # False-positive guidance
//!
//! - **WordPress / Joomla / Drupal / Magento / PHP apps**: drop or disable the
//!   matching [`RuleGroup`] entries before compile.
//! - **`/metrics`, `/health`, `/admin`**: intentionally *not* blocked by default.
//! - **Overlapping app paths**: add a narrow [`Rule::allow`] exclusion.

use std::sync::OnceLock;

use crate::{
    CompiledRuleSet,
    matcher::PathMatcher,
    rule::{Rule, RuleGroup},
    ruleset::RuleSet,
};

macro_rules! deny {
    ($id:expr, $group:expr, $desc:expr, $matcher:expr) => {
        Rule::deny($id, $group, $desc, $matcher).builtin()
    };
}

macro_rules! exact {
    ($p:expr) => {
        PathMatcher::Exact($p.into())
    };
}
macro_rules! prefix {
    ($p:expr) => {
        PathMatcher::Prefix($p.into())
    };
}
macro_rules! suffix {
    ($p:expr) => {
        PathMatcher::Suffix($p.into())
    };
}

fn build_default_rules() -> RuleSet {
    let rules: Vec<Rule> = vec![
        // ── Group 1: Secrets and environment files ──────────────────────────
        deny!(
            "secrets.dotenv",
            RuleGroup::Secrets,
            "Block .env file probes",
            exact!("/.env")
        ),
        deny!(
            "secrets.dotenv_production",
            RuleGroup::Secrets,
            "Block .env.production",
            exact!("/.env.production")
        ),
        deny!(
            "secrets.dotenv_local",
            RuleGroup::Secrets,
            "Block .env.local",
            exact!("/.env.local")
        ),
        deny!(
            "secrets.dotenv_development",
            RuleGroup::Secrets,
            "Block .env.development",
            exact!("/.env.development")
        ),
        deny!(
            "secrets.dotenv_staging",
            RuleGroup::Secrets,
            "Block .env.staging",
            exact!("/.env.staging")
        ),
        deny!(
            "secrets.dotenv_test",
            RuleGroup::Secrets,
            "Block .env.test",
            exact!("/.env.test")
        ),
        deny!(
            "secrets.dotenv_example",
            RuleGroup::Secrets,
            "Block .env.example",
            exact!("/.env.example")
        ),
        deny!(
            "secrets.dotenv_backup",
            RuleGroup::Secrets,
            "Block .env.backup",
            exact!("/.env.backup")
        ),
        deny!(
            "secrets.dotenv_prefix",
            RuleGroup::Secrets,
            "Block .env. prefix (catches variants)",
            prefix!("/.env.")
        ),
        deny!(
            "secrets.npmrc",
            RuleGroup::Secrets,
            "Block .npmrc",
            exact!("/.npmrc")
        ),
        deny!(
            "secrets.yarnrc",
            RuleGroup::Secrets,
            "Block .yarnrc",
            exact!("/.yarnrc")
        ),
        deny!(
            "secrets.pypirc",
            RuleGroup::Secrets,
            "Block .pypirc",
            exact!("/.pypirc")
        ),
        deny!(
            "secrets.netrc",
            RuleGroup::Secrets,
            "Block .netrc",
            exact!("/.netrc")
        ),
        deny!(
            "secrets.pgpass",
            RuleGroup::Secrets,
            "Block .pgpass",
            exact!("/.pgpass")
        ),
        deny!(
            "secrets.htpasswd",
            RuleGroup::Secrets,
            "Block .htpasswd",
            exact!("/.htpasswd")
        ),
        deny!(
            "secrets.git_credentials",
            RuleGroup::Secrets,
            "Block .git-credentials",
            exact!("/.git-credentials")
        ),
        deny!(
            "secrets.dockercfg",
            RuleGroup::Secrets,
            "Block .dockercfg",
            exact!("/.dockercfg")
        ),
        deny!(
            "secrets.docker_config",
            RuleGroup::Secrets,
            "Block .docker/config.json",
            exact!("/.docker/config.json")
        ),
        deny!(
            "secrets.credentials_json",
            RuleGroup::Secrets,
            "Block generic credentials.json",
            exact!("/credentials.json")
        ),
        deny!(
            "secrets.auth_json",
            RuleGroup::Secrets,
            "Block generic auth.json",
            exact!("/auth.json")
        ),
        deny!(
            "secrets.dot_auth_json",
            RuleGroup::Secrets,
            "Block .auth.json",
            exact!("/.auth.json")
        ),
        deny!(
            "secrets.composer_auth",
            RuleGroup::Secrets,
            "Block Composer authentication config",
            exact!("/.composer-auth.json")
        ),
        deny!(
            "secrets.composer_prefix",
            RuleGroup::Secrets,
            "Block Composer home metadata",
            prefix!("/.composer/")
        ),
        deny!(
            "secrets.rubygems_prefix",
            RuleGroup::Secrets,
            "Block RubyGems credential store",
            prefix!("/.gem/")
        ),
        deny!(
            "secrets.secrets_yml",
            RuleGroup::Secrets,
            "Block secrets.yml",
            exact!("/secrets.yml")
        ),
        deny!(
            "secrets.config_secrets_yml",
            RuleGroup::Secrets,
            "Block config/secrets.yml",
            exact!("/config/secrets.yml")
        ),
        // ── Group 2: Source-control metadata ────────────────────────────────
        deny!(
            "scm.git_prefix",
            RuleGroup::SourceControl,
            "Block .git/ prefix",
            prefix!("/.git/")
        ),
        deny!(
            "scm.git_config",
            RuleGroup::SourceControl,
            "Block .git/config",
            exact!("/.git/config")
        ),
        deny!(
            "scm.git_head",
            RuleGroup::SourceControl,
            "Block .git/HEAD",
            exact!("/.git/HEAD")
        ),
        deny!(
            "scm.svn_prefix",
            RuleGroup::SourceControl,
            "Block .svn/ prefix",
            prefix!("/.svn/")
        ),
        deny!(
            "scm.hg_prefix",
            RuleGroup::SourceControl,
            "Block .hg/ prefix",
            prefix!("/.hg/")
        ),
        deny!(
            "scm.bzr_prefix",
            RuleGroup::SourceControl,
            "Block .bzr/ prefix",
            prefix!("/.bzr/")
        ),
        deny!(
            "scm.cvs_prefix",
            RuleGroup::SourceControl,
            "Block CVS/ prefix",
            prefix!("/CVS/")
        ),
        // ── Group 3: Cloud credentials ───────────────────────────────────────
        deny!(
            "cloud.aws_credentials",
            RuleGroup::CloudCredentials,
            "Block .aws/credentials",
            exact!("/.aws/credentials")
        ),
        deny!(
            "cloud.aws_config",
            RuleGroup::CloudCredentials,
            "Block .aws/config",
            exact!("/.aws/config")
        ),
        deny!(
            "cloud.gcp_credentials",
            RuleGroup::CloudCredentials,
            "Block GCP credentials JSON",
            exact!("/gcp-credentials.json")
        ),
        deny!(
            "cloud.firebase_admin",
            RuleGroup::CloudCredentials,
            "Block Firebase admin key",
            exact!("/firebase-admin.json")
        ),
        deny!(
            "cloud.service_account",
            RuleGroup::CloudCredentials,
            "Block service-account JSON",
            exact!("/service-account.json")
        ),
        deny!(
            "cloud.azure_credentials",
            RuleGroup::CloudCredentials,
            "Block Azure credentials",
            exact!("/.azure/credentials")
        ),
        deny!(
            "cloud.azure_prefix",
            RuleGroup::CloudCredentials,
            "Block .azure/ prefix",
            prefix!("/.azure/")
        ),
        deny!(
            "cloud.gcloud_prefix",
            RuleGroup::CloudCredentials,
            "Block gcloud credential databases",
            prefix!("/.config/gcloud/")
        ),
        deny!(
            "cloud.gcloud_access_tokens",
            RuleGroup::CloudCredentials,
            "Block gcloud access token database",
            exact!("/access_tokens.db")
        ),
        deny!(
            "cloud.gcloud_credentials_db",
            RuleGroup::CloudCredentials,
            "Block gcloud credentials database",
            exact!("/credentials.db")
        ),
        deny!(
            "cloud.service_account_credentials",
            RuleGroup::CloudCredentials,
            "Block service-account credentials JSON",
            exact!("/service-account-credentials.json")
        ),
        // ── Group 4: SSH keys ────────────────────────────────────────────────
        deny!(
            "ssh.ssh_prefix",
            RuleGroup::SshKeys,
            "Block .ssh/ prefix",
            prefix!("/.ssh/")
        ),
        deny!(
            "ssh.id_rsa",
            RuleGroup::SshKeys,
            "Block id_rsa",
            exact!("/id_rsa")
        ),
        deny!(
            "ssh.id_rsa_pub",
            RuleGroup::SshKeys,
            "Block id_rsa.pub",
            exact!("/id_rsa.pub")
        ),
        deny!(
            "ssh.id_ed25519",
            RuleGroup::SshKeys,
            "Block id_ed25519",
            exact!("/id_ed25519")
        ),
        deny!(
            "ssh.id_ed25519_pub",
            RuleGroup::SshKeys,
            "Block id_ed25519.pub",
            exact!("/id_ed25519.pub")
        ),
        deny!(
            "ssh.id_ecdsa",
            RuleGroup::SshKeys,
            "Block id_ecdsa",
            exact!("/id_ecdsa")
        ),
        deny!(
            "ssh.server_key",
            RuleGroup::SshKeys,
            "Block server.key",
            exact!("/server.key")
        ),
        deny!(
            "ssh.private_key",
            RuleGroup::SshKeys,
            "Block private-key",
            exact!("/private-key")
        ),
        deny!(
            "ssh.private_key_pem",
            RuleGroup::SshKeys,
            "Block private-key.pem",
            exact!("/private-key.pem")
        ),
        deny!(
            "ssh.key_suffix_pem",
            RuleGroup::SshKeys,
            "Block *.pem suffix",
            suffix!(".pem")
        ),
        deny!(
            "ssh.key_suffix_key",
            RuleGroup::SshKeys,
            "Block *.key suffix",
            suffix!(".key")
        ),
        deny!(
            "ssh.known_hosts",
            RuleGroup::SshKeys,
            "Block known_hosts",
            exact!("/known_hosts")
        ),
        // ── Group 5: Build and deployment manifests ──────────────────────────
        deny!(
            "build.dockerfile",
            RuleGroup::BuildManifests,
            "Block Dockerfile probe",
            exact!("/Dockerfile")
        ),
        deny!(
            "build.docker_compose",
            RuleGroup::BuildManifests,
            "Block docker-compose.yml",
            exact!("/docker-compose.yml")
        ),
        deny!(
            "build.docker_compose_yaml",
            RuleGroup::BuildManifests,
            "Block docker-compose.yaml",
            exact!("/docker-compose.yaml")
        ),
        deny!(
            "build.terraform_tfstate",
            RuleGroup::BuildManifests,
            "Block terraform.tfstate",
            exact!("/terraform.tfstate")
        ),
        deny!(
            "build.terraform_tfstate_backup",
            RuleGroup::BuildManifests,
            "Block terraform.tfstate.backup",
            exact!("/terraform.tfstate.backup")
        ),
        deny!(
            "build.terraform_tfvars",
            RuleGroup::BuildManifests,
            "Block terraform.tfvars",
            exact!("/terraform.tfvars")
        ),
        deny!(
            "build.rclone_conf",
            RuleGroup::BuildManifests,
            "Block rclone.conf",
            exact!("/rclone.conf")
        ),
        deny!(
            "build.makefile",
            RuleGroup::BuildManifests,
            "Block Makefile probe",
            exact!("/Makefile")
        ),
        deny!(
            "build.vagrantfile",
            RuleGroup::BuildManifests,
            "Block Vagrantfile probe",
            exact!("/Vagrantfile")
        ),
        deny!(
            "build.ansible_vault",
            RuleGroup::BuildManifests,
            "Block ansible vault files",
            suffix!(".vault")
        ),
        deny!(
            "build.idea_prefix",
            RuleGroup::BuildManifests,
            "Block JetBrains project metadata",
            prefix!("/.idea/")
        ),
        deny!(
            "build.vscode_prefix",
            RuleGroup::BuildManifests,
            "Block VS Code project metadata",
            prefix!("/.vscode/")
        ),
        deny!(
            "build.vscode_server_prefix",
            RuleGroup::BuildManifests,
            "Block VS Code server metadata",
            prefix!("/.vscode-server/")
        ),
        // ── Group 6: Framework configuration ────────────────────────────────
        deny!(
            "fw.rails_master_key",
            RuleGroup::FrameworkConfig,
            "Block Rails master.key",
            exact!("/config/master.key")
        ),
        deny!(
            "fw.rails_database_yml",
            RuleGroup::FrameworkConfig,
            "Block Rails database.yml",
            exact!("/config/database.yml")
        ),
        deny!(
            "fw.django_settings",
            RuleGroup::FrameworkConfig,
            "Block Django settings.py",
            exact!("/settings.py")
        ),
        deny!(
            "fw.django_settings_config",
            RuleGroup::FrameworkConfig,
            "Block config/settings.py",
            exact!("/config/settings.py")
        ),
        deny!(
            "fw.laravel_log",
            RuleGroup::FrameworkConfig,
            "Block Laravel log",
            exact!("/storage/logs/laravel.log")
        ),
        deny!(
            "fw.laravel_log_prefix",
            RuleGroup::FrameworkConfig,
            "Block Laravel log prefix",
            prefix!("/storage/logs/")
        ),
        deny!(
            "fw.appsettings",
            RuleGroup::FrameworkConfig,
            "Block ASP.NET appsettings.json",
            exact!("/appsettings.json")
        ),
        deny!(
            "fw.appsettings_prefix",
            RuleGroup::FrameworkConfig,
            "Block appsettings.*.json",
            prefix!("/appsettings.")
        ),
        deny!(
            "fw.application_properties",
            RuleGroup::FrameworkConfig,
            "Block application.properties",
            exact!("/application.properties")
        ),
        deny!(
            "fw.application_yml",
            RuleGroup::FrameworkConfig,
            "Block application.yml",
            exact!("/application.yml")
        ),
        deny!(
            "fw.gradle_properties",
            RuleGroup::FrameworkConfig,
            "Block gradle.properties",
            exact!("/gradle.properties")
        ),
        deny!(
            "fw.config_runtime_exs",
            RuleGroup::FrameworkConfig,
            "Block Elixir runtime.exs",
            exact!("/config/runtime.exs")
        ),
        deny!(
            "fw.web_config",
            RuleGroup::FrameworkConfig,
            "Block IIS web.config",
            exact!("/web.config")
        ),
        deny!(
            "fw.wp_config_php",
            RuleGroup::FrameworkConfig,
            "Block wp-config.php",
            exact!("/wp-config.php")
        ),
        deny!(
            "fw.config_php",
            RuleGroup::FrameworkConfig,
            "Block config.php probe",
            exact!("/config.php")
        ),
        deny!(
            "fw.local_xml",
            RuleGroup::FrameworkConfig,
            "Block local.xml",
            exact!("/local.xml")
        ),
        deny!(
            "fw.php_ini",
            RuleGroup::FrameworkConfig,
            "Block php.ini",
            exact!("/php.ini")
        ),
        deny!(
            "fw.phpunit_xml",
            RuleGroup::FrameworkConfig,
            "Block PHPUnit configuration",
            exact!("/phpunit.xml")
        ),
        deny!(
            "fw.redis_conf",
            RuleGroup::FrameworkConfig,
            "Block Redis configuration",
            exact!("/redis.conf")
        ),
        deny!(
            "fw.uwsgi_ini",
            RuleGroup::FrameworkConfig,
            "Block uWSGI configuration",
            exact!("/uwsgi.ini")
        ),
        deny!(
            "fw.gunicorn_conf",
            RuleGroup::FrameworkConfig,
            "Block Gunicorn configuration",
            exact!("/gunicorn.conf.py")
        ),
        deny!(
            "fw.config_php_backups",
            RuleGroup::FrameworkConfig,
            "Block config.php backup variants",
            prefix!("/config.php.")
        ),
        deny!(
            "fw.settings_php_backups",
            RuleGroup::FrameworkConfig,
            "Block settings.php backup variants",
            prefix!("/settings.php.")
        ),
        deny!(
            "fw.wp_config_backups",
            RuleGroup::FrameworkConfig,
            "Block wp-config.php backup variants",
            prefix!("/wp-config.php.")
        ),
        // ── Group 7: WordPress ───────────────────────────────────────────────
        deny!(
            "wp.login",
            RuleGroup::WordPress,
            "Block wp-login.php",
            exact!("/wp-login.php")
        ),
        deny!(
            "wp.admin_prefix",
            RuleGroup::WordPress,
            "Block wp-admin/ prefix",
            prefix!("/wp-admin/")
        ),
        deny!(
            "wp.xmlrpc",
            RuleGroup::WordPress,
            "Block xmlrpc.php",
            exact!("/xmlrpc.php")
        ),
        deny!(
            "wp.content_plugins",
            RuleGroup::WordPress,
            "Block wp-content/plugins/",
            prefix!("/wp-content/plugins/")
        ),
        deny!(
            "wp.content_themes",
            RuleGroup::WordPress,
            "Block wp-content/themes/",
            prefix!("/wp-content/themes/")
        ),
        deny!(
            "wp.includes_prefix",
            RuleGroup::WordPress,
            "Block wp-includes/ prefix",
            prefix!("/wp-includes/")
        ),
        deny!(
            "wp.trackback",
            RuleGroup::WordPress,
            "Block trackback.php",
            exact!("/trackback.php")
        ),
        deny!(
            "wp.readme",
            RuleGroup::WordPress,
            "Block WordPress readme.html",
            exact!("/readme.html")
        ),
        deny!(
            "wp.license",
            RuleGroup::WordPress,
            "Block WordPress license.txt",
            exact!("/license.txt")
        ),
        // ── Group 8: Joomla ──────────────────────────────────────────────────
        deny!(
            "joomla.administrator",
            RuleGroup::Joomla,
            "Block Joomla administrator prefix",
            prefix!("/administrator/")
        ),
        deny!(
            "joomla.installation",
            RuleGroup::Joomla,
            "Block Joomla installation prefix",
            prefix!("/installation/")
        ),
        deny!(
            "joomla.components",
            RuleGroup::Joomla,
            "Block Joomla components",
            prefix!("/components/")
        ),
        deny!(
            "joomla.modules",
            RuleGroup::Joomla,
            "Block Joomla modules",
            prefix!("/modules/")
        ),
        // ── Group 9: Drupal ──────────────────────────────────────────────────
        deny!(
            "drupal.sites_default",
            RuleGroup::Drupal,
            "Block Drupal default settings",
            prefix!("/sites/default/")
        ),
        deny!(
            "drupal.update_php",
            RuleGroup::Drupal,
            "Block Drupal update.php",
            exact!("/update.php")
        ),
        deny!(
            "drupal.install_php",
            RuleGroup::Drupal,
            "Block Drupal install.php",
            exact!("/install.php")
        ),
        deny!(
            "drupal.cron_php",
            RuleGroup::Drupal,
            "Block Drupal cron.php",
            exact!("/cron.php")
        ),
        // ── Group 10: Magento ────────────────────────────────────────────────
        deny!(
            "magento.admin_prefix",
            RuleGroup::Magento,
            "Block Magento admin prefix",
            prefix!("/admin_")
        ),
        deny!(
            "magento.downloader",
            RuleGroup::Magento,
            "Block Magento downloader",
            prefix!("/downloader/")
        ),
        deny!(
            "magento.shell",
            RuleGroup::Magento,
            "Block Magento shell",
            prefix!("/shell/")
        ),
        deny!(
            "magento.errors_prefix",
            RuleGroup::Magento,
            "Block Magento errors prefix",
            prefix!("/errors/")
        ),
        deny!(
            "magento.var_export",
            RuleGroup::Magento,
            "Block Magento var exports",
            prefix!("/var/export/")
        ),
        // ── Group 11: PHP web-shell probes ───────────────────────────────────
        // A small, high-confidence set; applications can extend via custom rules.
        deny!(
            "phpshell.c99",
            RuleGroup::PhpShell,
            "Block c99 web shell",
            exact!("/c99.php")
        ),
        deny!(
            "phpshell.r57",
            RuleGroup::PhpShell,
            "Block r57 web shell",
            exact!("/r57.php")
        ),
        deny!(
            "phpshell.phpinfo",
            RuleGroup::PhpShell,
            "Block phpinfo.php",
            exact!("/phpinfo.php")
        ),
        deny!(
            "phpshell.shell",
            RuleGroup::PhpShell,
            "Block shell.php",
            exact!("/shell.php")
        ),
        deny!(
            "phpshell.cmd",
            RuleGroup::PhpShell,
            "Block cmd.php",
            exact!("/cmd.php")
        ),
        deny!(
            "phpshell.php_probe",
            RuleGroup::PhpShell,
            "Block php probe suffix",
            exact!("/php")
        ),
        deny!(
            "phpshell.eval",
            RuleGroup::PhpShell,
            "Block eval.php",
            exact!("/eval.php")
        ),
        deny!(
            "phpshell.b374k",
            RuleGroup::PhpShell,
            "Block b374k shell",
            exact!("/b374k.php")
        ),
        deny!(
            "phpshell.wso",
            RuleGroup::PhpShell,
            "Block wso shell",
            exact!("/wso.php")
        ),
        // ── Group 12: Debug, profiler, actuator, server-status ────────────────
        deny!(
            "debug.phpinfo_path",
            RuleGroup::Debug,
            "Block phpinfo.php at root",
            exact!("/phpinfo.php")
        ),
        deny!(
            "debug.pprof_prefix",
            RuleGroup::Debug,
            "Block Go pprof",
            prefix!("/debug/pprof/")
        ),
        deny!(
            "debug.debug_vars",
            RuleGroup::Debug,
            "Block Go debug/vars",
            exact!("/debug/vars")
        ),
        deny!(
            "debug.actuator_prefix",
            RuleGroup::Debug,
            "Block Spring actuator prefix",
            prefix!("/actuator/")
        ),
        deny!(
            "debug.actuator_exact",
            RuleGroup::Debug,
            "Block Spring actuator root",
            exact!("/actuator")
        ),
        deny!(
            "debug.server_status",
            RuleGroup::Debug,
            "Block Apache server-status",
            exact!("/server-status")
        ),
        deny!(
            "debug.server_info",
            RuleGroup::Debug,
            "Block Apache server-info",
            exact!("/server-info")
        ),
        deny!(
            "debug.nginx_status",
            RuleGroup::Debug,
            "Block nginx status",
            exact!("/nginx_status")
        ),
        deny!(
            "debug.laravel_telescope",
            RuleGroup::Debug,
            "Block Laravel Telescope",
            prefix!("/telescope/")
        ),
        deny!(
            "debug.laravel_horizon",
            RuleGroup::Debug,
            "Block Laravel Horizon",
            prefix!("/horizon/")
        ),
        deny!(
            "debug.rails_info",
            RuleGroup::Debug,
            "Block Rails info routes",
            prefix!("/rails/info/")
        ),
        deny!(
            "debug.sidekiq",
            RuleGroup::Debug,
            "Block Sidekiq web UI",
            prefix!("/sidekiq/")
        ),
        deny!(
            "debug.profiler_prefix",
            RuleGroup::Debug,
            "Block /_profiler prefix (Symfony)",
            prefix!("/_profiler/")
        ),
        deny!(
            "debug.wdt_prefix",
            RuleGroup::Debug,
            "Block /_wdt prefix (Symfony)",
            prefix!("/_wdt/")
        ),
        deny!(
            "debug.pyramid_toolbar",
            RuleGroup::Debug,
            "Block Pyramid debug toolbar",
            prefix!("/_debug_toolbar/")
        ),
        deny!(
            "debug.clockwork",
            RuleGroup::Debug,
            "Block Clockwork debug UI",
            prefix!("/__clockwork/")
        ),
        deny!(
            "debug.elmah",
            RuleGroup::Debug,
            "Block ASP.NET ELMAH diagnostics",
            exact!("/elmah.axd")
        ),
        deny!(
            "debug.trace_axd",
            RuleGroup::Debug,
            "Block ASP.NET trace diagnostics",
            exact!("/trace.axd")
        ),
        // ── Group 13: AI and developer-tool credentials ──────────────────────
        deny!(
            "ai.codex_config",
            RuleGroup::AiTools,
            "Block Codex config",
            exact!("/.codex/config.toml")
        ),
        deny!(
            "ai.cursor_mcp",
            RuleGroup::AiTools,
            "Block Cursor MCP config",
            exact!("/.cursor/mcp.json")
        ),
        deny!(
            "ai.mcp_json",
            RuleGroup::AiTools,
            "Block .mcp.json",
            exact!("/.mcp.json")
        ),
        deny!(
            "ai.claude_json",
            RuleGroup::AiTools,
            "Block .claude.json",
            exact!("/.claude.json")
        ),
        deny!(
            "ai.claude_md",
            RuleGroup::AiTools,
            "Block CLAUDE.md",
            exact!("/CLAUDE.md")
        ),
        deny!(
            "ai.anthropic_credentials",
            RuleGroup::AiTools,
            "Block Anthropic credentials",
            exact!("/.config/anthropic/credentials/default")
        ),
        deny!(
            "ai.openai_config",
            RuleGroup::AiTools,
            "Block OpenAI config prefix",
            prefix!("/.config/openai/")
        ),
        deny!(
            "ai.cursor_prefix",
            RuleGroup::AiTools,
            "Block .cursor/ prefix",
            prefix!("/.cursor/")
        ),
        deny!(
            "ai.copilot_prefix",
            RuleGroup::AiTools,
            "Block .copilot/ prefix",
            prefix!("/.copilot/")
        ),
        deny!(
            "ai.continue_prefix",
            RuleGroup::AiTools,
            "Block .continue/ prefix",
            prefix!("/.continue/")
        ),
        deny!(
            "ai.codex_prefix",
            RuleGroup::AiTools,
            "Block Codex credentials and config",
            prefix!("/.codex/")
        ),
        deny!(
            "ai.claude_prefix",
            RuleGroup::AiTools,
            "Block Claude credentials and config",
            prefix!("/.claude/")
        ),
    ];

    rules.into_iter().fold(RuleSet::new(), |rs, r| rs.push(r))
}

static DEFAULT_RULES_CELL: OnceLock<RuleSet> = OnceLock::new();
static DEFAULT_COMPILED_RULES_CELL: OnceLock<CompiledRuleSet> = OnceLock::new();

/// Clone of the process-wide built-in [`RuleSet`] (all rules enabled).
///
/// Initialised once via [`OnceLock`]; each call clones so callers can
/// `push` custom rules without mutating the shared template. Compile the
/// clone before request handling.
pub fn default_rules() -> RuleSet {
    DEFAULT_RULES_CELL.get_or_init(build_default_rules).clone()
}

/// Ergonomic handle so callers write `DEFAULT_RULES.get()` for a clone.
///
/// Equivalent to [`default_rules()`]. Prefer this form at call sites that
/// already import the `DEFAULT_RULES` symbol from the crate root.
pub static DEFAULT_RULES: DefaultRulesProxy = DefaultRulesProxy;

/// Zero-sized proxy exposing [`DefaultRulesProxy::get`] on [`DEFAULT_RULES`].
#[derive(Debug, Clone, Copy)]
pub struct DefaultRulesProxy;

impl DefaultRulesProxy {
    /// Return a clone of the built-in rule set for further customisation.
    pub fn get(&self) -> RuleSet {
        default_rules()
    }

    /// Return the process-wide compiled built-ins.
    ///
    /// The first call compiles once; subsequent calls clone only two shared
    /// rule-table handles. Use [`Self::get`] when rules need customisation.
    pub fn compiled(&self) -> CompiledRuleSet {
        DEFAULT_COMPILED_RULES_CELL
            .get_or_init(|| {
                build_default_rules()
                    .compile()
                    .expect("built-in rules must compile")
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompiledRuleSet, InspectionPath, ShieldDecision};

    fn compiled() -> CompiledRuleSet {
        default_rules().compile().unwrap()
    }

    fn blocked(rs: &CompiledRuleSet, path: &str) -> bool {
        matches!(
            rs.evaluate(&InspectionPath::new(path)),
            ShieldDecision::Block(_)
        )
    }

    fn allowed(rs: &CompiledRuleSet, path: &str) -> bool {
        rs.evaluate(&InspectionPath::new(path)) == ShieldDecision::Allow
    }

    #[test]
    fn secrets_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/.env"));
        assert!(blocked(&rs, "/.env.production"));
        assert!(blocked(&rs, "/.npmrc"));
        assert!(blocked(&rs, "/.git-credentials"));
    }

    #[test]
    fn source_control_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/.git/config"));
        assert!(blocked(&rs, "/.git/HEAD"));
        assert!(blocked(&rs, "/.svn/entries"));
        assert!(blocked(&rs, "/.hg/hgrc"));
    }

    #[test]
    fn cloud_credentials_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/.aws/credentials"));
        assert!(blocked(&rs, "/.aws/config"));
        assert!(blocked(&rs, "/gcp-credentials.json"));
        assert!(blocked(&rs, "/service-account.json"));
    }

    #[test]
    fn ssh_keys_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/.ssh/id_rsa"));
        assert!(blocked(&rs, "/id_rsa"));
        assert!(blocked(&rs, "/id_ed25519"));
        assert!(blocked(&rs, "/server.key"));
        assert!(blocked(&rs, "/cert.pem"));
    }

    #[test]
    fn build_manifests_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/Dockerfile"));
        assert!(blocked(&rs, "/terraform.tfstate"));
        assert!(blocked(&rs, "/rclone.conf"));
    }

    #[test]
    fn framework_config_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/config/master.key"));
        assert!(blocked(&rs, "/config/database.yml"));
        assert!(blocked(&rs, "/settings.py"));
        assert!(blocked(&rs, "/appsettings.json"));
        assert!(blocked(&rs, "/application.properties"));
        assert!(blocked(&rs, "/gradle.properties"));
        assert!(blocked(&rs, "/config/runtime.exs"));
        assert!(blocked(&rs, "/storage/logs/laravel.log"));
    }

    #[test]
    fn wordpress_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/wp-login.php"));
        assert!(blocked(&rs, "/wp-admin/options-general.php"));
        assert!(blocked(&rs, "/xmlrpc.php"));
        assert!(blocked(&rs, "/wp-content/plugins/exploit/shell.php"));
        assert!(blocked(&rs, "/wp-includes/script-loader.php"));
    }

    #[test]
    fn joomla_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/administrator/index.php"));
        assert!(blocked(&rs, "/installation/index.php"));
    }

    #[test]
    fn drupal_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/sites/default/settings.php"));
        assert!(blocked(&rs, "/update.php"));
        assert!(blocked(&rs, "/install.php"));
    }

    #[test]
    fn magento_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/downloader/index.php"));
        assert!(blocked(&rs, "/shell/run.php"));
    }

    #[test]
    fn php_shell_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/c99.php"));
        assert!(blocked(&rs, "/r57.php"));
        assert!(blocked(&rs, "/shell.php"));
    }

    #[test]
    fn debug_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/debug/pprof/heap"));
        assert!(blocked(&rs, "/actuator/env"));
        assert!(blocked(&rs, "/actuator"));
        assert!(blocked(&rs, "/server-status"));
        assert!(blocked(&rs, "/server-info"));
    }

    #[test]
    fn ai_tools_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/.codex/config.toml"));
        assert!(blocked(&rs, "/.cursor/mcp.json"));
        assert!(blocked(&rs, "/.mcp.json"));
        assert!(blocked(&rs, "/.claude.json"));
        assert!(blocked(&rs, "/.config/anthropic/credentials/default"));
    }

    #[test]
    fn does_not_block_generic_app_paths() {
        let rs = compiled();
        assert!(allowed(&rs, "/admin"));
        assert!(allowed(&rs, "/api"));
        assert!(allowed(&rs, "/graphql"));
        assert!(allowed(&rs, "/metrics"));
        assert!(allowed(&rs, "/health"));
        assert!(allowed(&rs, "/dashboard"));
        assert!(allowed(&rs, "/config"));
        assert!(allowed(&rs, "/"));
    }
}
