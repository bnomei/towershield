//! Conservative built-in scanner-probe denylist shipped with the library.
//!
//! Rules are plain [`Rule`] values built with the same public API applications
//! use. Nothing is special-cased inside the matcher; disable or override via
//! [`Rule::enabled`], allow rules, or a custom [`RuleSet`]. Access the shared
//! template through [`DEFAULT_RULES`] (clone + customise, or take the process
//! compiled form).
//!
//! With the default-on `regex` feature, the set also includes broader rules
//! for nested sensitive files, framework installations, and filename
//! families. Disabling default features omits that expansion tier while
//! retaining the exact, prefix, suffix, segment, contains, and wildcard rules.
//!
//! # Versioning policy
//!
//! Before 1.0, built-in rule changes may ship in patch releases while the set
//! is being established. After 1.0, **adding** a rule is a minor bump (more
//! paths may block); **removing** or weakening a match is a major bump.
//!
//! # False-positive guidance
//!
//! - **WordPress / Joomla / Drupal / Magento / PHP apps**: drop or disable the
//!   matching [`RuleGroup`] entries before compile.
//! - **Deliberately exposed Next.js / Vite development servers**: disable the
//!   [`RuleGroup::JavaScript`] entries; production assets such as
//!   `/_next/static`, `/_next/image`, and ordinary JS bundles are not blocked.
//! - **`/metrics`, `/health`, `/admin`**: intentionally *not* blocked by default.
//! - **Agent and API discovery**: public `/.well-known/*`, OAuth/OIDC, MCP,
//!   Agent Skills, A2A, UCP, ACP, and payment-discovery paths are not blanket
//!   blocked or allowed. Representative public paths have regression coverage.
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

#[cfg(feature = "regex")]
macro_rules! regex {
    ($p:expr) => {
        PathMatcher::Regex($p.into())
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
            "secrets.yarnrc_yml",
            RuleGroup::Secrets,
            "Block modern Yarn configuration and credentials",
            exact!("/.yarnrc.yml")
        ),
        deny!(
            "secrets.bunfig",
            RuleGroup::Secrets,
            "Block Bun configuration and registry credentials",
            exact!("/bunfig.toml")
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
        // ── Group 7: JavaScript / React / Next.js tooling ───────────────────
        deny!(
            "js.package_json",
            RuleGroup::JavaScript,
            "Block package.json disclosure",
            exact!("/package.json")
        ),
        deny!(
            "js.package_lock",
            RuleGroup::JavaScript,
            "Block package-lock.json disclosure",
            exact!("/package-lock.json")
        ),
        deny!(
            "js.npm_shrinkwrap",
            RuleGroup::JavaScript,
            "Block npm-shrinkwrap.json disclosure",
            exact!("/npm-shrinkwrap.json")
        ),
        deny!(
            "js.yarn_lock",
            RuleGroup::JavaScript,
            "Block yarn.lock disclosure",
            exact!("/yarn.lock")
        ),
        deny!(
            "js.pnpm_lock",
            RuleGroup::JavaScript,
            "Block pnpm-lock.yaml disclosure",
            exact!("/pnpm-lock.yaml")
        ),
        deny!(
            "js.bun_lock",
            RuleGroup::JavaScript,
            "Block Bun text lockfile disclosure",
            exact!("/bun.lock")
        ),
        deny!(
            "js.bun_lockb",
            RuleGroup::JavaScript,
            "Block legacy Bun binary lockfile disclosure",
            exact!("/bun.lockb")
        ),
        deny!(
            "js.npmignore",
            RuleGroup::JavaScript,
            "Block .npmignore disclosure",
            exact!("/.npmignore")
        ),
        deny!(
            "js.yarn_integrity",
            RuleGroup::JavaScript,
            "Block Yarn integrity metadata",
            exact!("/.yarn-integrity")
        ),
        deny!(
            "js.node_modules_prefix",
            RuleGroup::JavaScript,
            "Block direct node_modules access",
            prefix!("/node_modules/")
        ),
        deny!(
            "js.npm_debug_log",
            RuleGroup::JavaScript,
            "Block npm debug log disclosure",
            exact!("/npm-debug.log")
        ),
        deny!(
            "js.npm_debug_log_assets",
            RuleGroup::JavaScript,
            "Block npm debug log under assets",
            exact!("/assets/npm-debug.log")
        ),
        deny!(
            "js.jsconfig",
            RuleGroup::JavaScript,
            "Block jsconfig.json disclosure",
            exact!("/jsconfig.json")
        ),
        deny!(
            "js.tsconfig",
            RuleGroup::JavaScript,
            "Block tsconfig.json disclosure",
            exact!("/tsconfig.json")
        ),
        deny!(
            "js.babel_config_js",
            RuleGroup::JavaScript,
            "Block Babel JavaScript configuration",
            exact!("/babel.config.js")
        ),
        deny!(
            "js.babel_config_cjs",
            RuleGroup::JavaScript,
            "Block Babel CommonJS configuration",
            exact!("/babel.config.cjs")
        ),
        deny!(
            "js.babel_config_mjs",
            RuleGroup::JavaScript,
            "Block Babel ESM configuration",
            exact!("/babel.config.mjs")
        ),
        deny!(
            "js.next_config_js",
            RuleGroup::JavaScript,
            "Block Next.js JavaScript configuration",
            exact!("/next.config.js")
        ),
        deny!(
            "js.next_config_cjs",
            RuleGroup::JavaScript,
            "Block Next.js CommonJS configuration",
            exact!("/next.config.cjs")
        ),
        deny!(
            "js.next_config_mjs",
            RuleGroup::JavaScript,
            "Block Next.js ESM configuration",
            exact!("/next.config.mjs")
        ),
        deny!(
            "js.next_config_ts",
            RuleGroup::JavaScript,
            "Block Next.js TypeScript configuration",
            exact!("/next.config.ts")
        ),
        deny!(
            "js.next_env_types",
            RuleGroup::JavaScript,
            "Block Next.js generated type declarations",
            exact!("/next-env.d.ts")
        ),
        deny!(
            "js.next_build_prefix",
            RuleGroup::JavaScript,
            "Block internal Next.js build output",
            prefix!("/.next/")
        ),
        deny!(
            "js.next_original_stack_frame",
            RuleGroup::JavaScript,
            "Block Next.js development stack-frame endpoint",
            exact!("/__nextjs_original-stack-frame")
        ),
        deny!(
            "js.next_launch_editor",
            RuleGroup::JavaScript,
            "Block Next.js development editor endpoint",
            exact!("/__nextjs_launch-editor")
        ),
        deny!(
            "js.next_webpack_hmr",
            RuleGroup::JavaScript,
            "Block Next.js development HMR endpoint",
            exact!("/_next/webpack-hmr")
        ),
        deny!(
            "js.next_dev_mcp",
            RuleGroup::JavaScript,
            "Block Next.js development MCP endpoint",
            exact!("/_next/mcp")
        ),
        deny!(
            "js.vite_config_js",
            RuleGroup::JavaScript,
            "Block Vite JavaScript configuration",
            exact!("/vite.config.js")
        ),
        deny!(
            "js.vite_config_ts",
            RuleGroup::JavaScript,
            "Block Vite TypeScript configuration",
            exact!("/vite.config.ts")
        ),
        deny!(
            "js.vite_config_mjs",
            RuleGroup::JavaScript,
            "Block Vite ESM configuration",
            exact!("/vite.config.mjs")
        ),
        deny!(
            "js.vite_config_mts",
            RuleGroup::JavaScript,
            "Block Vite ESM TypeScript configuration",
            exact!("/vite.config.mts")
        ),
        deny!(
            "js.vite_config_cjs",
            RuleGroup::JavaScript,
            "Block Vite CommonJS configuration",
            exact!("/vite.config.cjs")
        ),
        deny!(
            "js.vite_config_cts",
            RuleGroup::JavaScript,
            "Block Vite CommonJS TypeScript configuration",
            exact!("/vite.config.cts")
        ),
        deny!(
            "js.vite_client",
            RuleGroup::JavaScript,
            "Block Vite development client",
            exact!("/@vite/client")
        ),
        deny!(
            "js.vite_react_refresh",
            RuleGroup::JavaScript,
            "Block Vite React Fast Refresh runtime",
            exact!("/@react-refresh")
        ),
        deny!(
            "js.vite_fs_prefix",
            RuleGroup::JavaScript,
            "Block Vite development filesystem access",
            prefix!("/@fs/")
        ),
        deny!(
            "js.webpack_config_js",
            RuleGroup::JavaScript,
            "Block webpack JavaScript configuration",
            exact!("/webpack.config.js")
        ),
        deny!(
            "js.webpack_config_ts",
            RuleGroup::JavaScript,
            "Block webpack TypeScript configuration",
            exact!("/webpack.config.ts")
        ),
        deny!(
            "js.webpack_config_cjs",
            RuleGroup::JavaScript,
            "Block webpack CommonJS configuration",
            exact!("/webpack.config.cjs")
        ),
        deny!(
            "js.webpack_config_mjs",
            RuleGroup::JavaScript,
            "Block webpack ESM configuration",
            exact!("/webpack.config.mjs")
        ),
        // ── Group 8: WordPress ───────────────────────────────────────────────
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
        // ── Group 9: Joomla ──────────────────────────────────────────────────
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
        // ── Group 10: Drupal ─────────────────────────────────────────────────
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
        // ── Group 11: Magento ────────────────────────────────────────────────
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
        // ── Group 12: PHP web-shell probes ───────────────────────────────────
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
        // ── Group 13: Debug, profiler, actuator, server-status ────────────────
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
        // ── Group 14: AI and developer-tool credentials ──────────────────────
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

    // Broader nested-path and filename-family coverage. Keeping these rules
    // behind the default-on `regex` feature gives dependency-minimal builds a
    // smaller rule set while retaining the exact/prefix baseline above.
    #[cfg(feature = "regex")]
    let rules = {
        let mut rules = rules;
        rules.extend([
        deny!(
            "regex.secrets_nested",
            RuleGroup::Secrets,
            "Block nested secret dotfiles and environment variants",
            regex!(r"(?:^|/)(?:\.(?:env(?:\.[A-Za-z0-9._-]+)?|npmrc|yarnrc(?:\.yml)?|pypirc|netrc|pgpass|htpasswd|git-credentials)|bunfig\.toml)$")
        ),
        deny!(
            "regex.source_control_nested",
            RuleGroup::SourceControl,
            "Block nested source-control metadata",
            regex!(r"(?:^|/)\.(?:git/(?:HEAD|config|index)|svn/(?:entries|wc\.db)|hg/hgrc)$")
        ),
        deny!(
            "regex.cloud_credentials_nested",
            RuleGroup::CloudCredentials,
            "Block nested cloud credential files",
            regex!(r"(?:^|/)(?:\.aws/(?:credentials|config)|\.config/gcloud/(?:credentials\.db|access_tokens\.db)|gcp-credentials\.json|service-account\.json)$")
        ),
        deny!(
            "regex.ssh_keys_nested",
            RuleGroup::SshKeys,
            "Block nested SSH identity and trust files",
            regex!(r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|known_hosts)$")
        ),
        deny!(
            "regex.build_manifests_nested",
            RuleGroup::BuildManifests,
            "Block nested build and deployment manifests",
            regex!(r"(?:^|/)(?:terraform\.tfstate(?:\.[A-Za-z0-9._-]+)?|terraform\.tfvars|Dockerfile|docker-compose\.ya?ml)$")
        ),
        deny!(
            "regex.framework_backups_nested",
            RuleGroup::FrameworkConfig,
            "Block nested PHP framework configuration backups",
            regex!(r"(?:^|/)(?:wp-config|config|settings)\.php\.(?:bak|backup|old|orig|save|swp|tmp)$")
        ),
        deny!(
            "regex.javascript_manifests_nested",
            RuleGroup::JavaScript,
            "Block nested JavaScript package and compiler manifests",
            regex!(r"(?:^|/)(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|jsconfig\.json|tsconfig\.json)$")
        ),
        deny!(
            "regex.javascript_configs_nested",
            RuleGroup::JavaScript,
            "Block nested JavaScript framework and bundler configuration",
            regex!(r"(?:^|/)(?:next|vite|webpack|babel)\.config\.(?:js|cjs|mjs|ts|cts|mts)$")
        ),
        deny!(
            "regex.javascript_debug_nested",
            RuleGroup::JavaScript,
            "Block nested package-manager debug metadata",
            regex!(r"(?:^|/)(?:npm-debug\.log(?:\.[0-9]+)?|\.yarn-integrity)$")
        ),
        deny!(
            "regex.wordpress_nested",
            RuleGroup::WordPress,
            "Block WordPress probes under nested installations",
            regex!(r"(?:^|/)wp-(?:login\.php|admin(?:/|$)|content/plugins(?:/|$)|includes(?:/|$))")
        ),
        deny!(
            "regex.joomla_nested",
            RuleGroup::Joomla,
            "Block Joomla probes under nested installations",
            regex!(r"(?:^|/)(?:administrator/(?:index\.php|manifests/files/joomla\.xml)|installation/(?:index\.php|configuration\.php-dist))$")
        ),
        deny!(
            "regex.drupal_nested",
            RuleGroup::Drupal,
            "Block Drupal sites/default probes under nested installations",
            regex!(r"(?:^|/)sites/default(?:/|$)")
        ),
        deny!(
            "regex.magento_nested",
            RuleGroup::Magento,
            "Block Magento probes under nested installations",
            regex!(r"(?:^|/)(?:(?:downloader|shell)/index\.php|var/export/[A-Za-z0-9._-]+)$")
        ),
        deny!(
            "regex.php_shell_nested",
            RuleGroup::PhpShell,
            "Block common PHP web-shell filenames at any depth",
            regex!(r"(?:^|/)(?:c99|r57|phpinfo|shell|cmd|eval|b374k|wso)\.php$")
        ),
        deny!(
            "regex.debug_nested",
            RuleGroup::Debug,
            "Block common debug endpoints under nested routes",
            regex!(r"(?:^|/)(?:debug/pprof|_debug_toolbar|__clockwork|actuator)(?:/|$)")
        ),
        deny!(
            "regex.ai_tools_nested",
            RuleGroup::AiTools,
            "Block nested AI developer-tool metadata",
            regex!(r"(?:^|/)\.(?:codex|cursor|claude|continue|copilot)(?:/|$)")
        ),
        ]);
        rules
    };

    rules.into_iter().fold(RuleSet::new(), |rs, r| rs.push(r))
}

static DEFAULT_RULES_CELL: OnceLock<RuleSet> = OnceLock::new();
static DEFAULT_COMPILED_RULES_CELL: OnceLock<CompiledRuleSet> = OnceLock::new();

/// Clone of the process-wide built-in [`RuleSet`] (all rules enabled).
///
/// Initialised once via [`OnceLock`]; each call clones so callers can
/// `push` custom rules without mutating the shared template. Compile the
/// clone (or use [`DefaultRulesProxy::compiled`]) before request handling.
pub fn default_rules() -> RuleSet {
    DEFAULT_RULES_CELL.get_or_init(build_default_rules).clone()
}

/// Process-wide handle for the built-in scanner-probe denylist.
///
/// Prefer `DEFAULT_RULES.get()` to customise then compile, or
/// `DEFAULT_RULES.compiled()` for the shared hot-path form. Equivalent
/// clone path: [`default_rules`].
pub static DEFAULT_RULES: DefaultRulesProxy = DefaultRulesProxy;

/// Zero-sized proxy so [`DEFAULT_RULES`] exposes [`get`](Self::get) /
/// [`compiled`](Self::compiled) without a free-function call style.
#[derive(Debug, Clone, Copy)]
pub struct DefaultRulesProxy;

impl DefaultRulesProxy {
    /// Clone the built-in declarative rules for customisation.
    ///
    /// The returned [`RuleSet`] is independent; push allow/deny rules or
    /// disable groups, then compile. Does not share the compiled cache.
    pub fn get(&self) -> RuleSet {
        default_rules()
    }

    /// Shared, process-wide compiled built-ins for the request path.
    ///
    /// First call compiles once (panics only if built-ins are invalid, which
    /// is a crate bug). Later calls clone two [`std::sync::Arc`] rule tables.
    /// Use [`Self::get`] when rules need customisation before compile.
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
    fn javascript_group() {
        let rs = compiled();
        assert!(blocked(&rs, "/package.json"));
        assert!(blocked(&rs, "/package-lock.json"));
        assert!(blocked(&rs, "/pnpm-lock.yaml"));
        assert!(blocked(&rs, "/bun.lock"));
        assert!(blocked(&rs, "/bun.lockb"));
        assert!(blocked(&rs, "/node_modules/.yarn-integrity"));
        assert!(blocked(&rs, "/next.config.mjs"));
        assert!(blocked(&rs, "/.next/server/app-paths-manifest.json"));
        assert!(blocked(&rs, "/__nextjs_original-stack-frame"));
        assert!(blocked(&rs, "/_next/mcp"));
        assert!(blocked(&rs, "/@vite/client"));
        assert!(blocked(&rs, "/@fs/etc/passwd"));
        assert!(blocked(&rs, "/webpack.config.js"));

        assert!(allowed(&rs, "/_next/static/chunks/app.js"));
        assert!(allowed(&rs, "/_next/image"));
        assert!(allowed(&rs, "/assets/app.js"));
        assert!(allowed(&rs, "/manifest.json"));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn regex_expansion_blocks_nested_and_variant_probes() {
        let rs = compiled();
        assert!(blocked(&rs, "/app/.env.staging"));
        assert!(blocked(&rs, "/frontend/package-lock.json"));
        assert!(blocked(&rs, "/frontend/bun.lock"));
        assert!(blocked(&rs, "/legacy/bun.lockb"));
        assert!(blocked(&rs, "/frontend/vite.config.ts"));
        assert!(blocked(&rs, "/blog/wp-login.php"));
        assert!(blocked(&rs, "/cms/administrator/index.php"));
        assert!(blocked(&rs, "/shop/downloader/index.php"));
        assert!(blocked(&rs, "/public/c99.php"));
        assert!(blocked(&rs, "/workspace/.cursor/mcp.json"));
        assert!(blocked(&rs, "/frontend/.yarnrc.yml"));
        assert!(blocked(&rs, "/frontend/bunfig.toml"));
    }

    #[cfg(not(feature = "regex"))]
    #[test]
    fn disabling_regex_omits_expansion_but_keeps_baseline() {
        let rs = compiled();
        assert!(blocked(&rs, "/.env.production"));
        assert!(blocked(&rs, "/package-lock.json"));
        assert!(blocked(&rs, "/bun.lock"));
        assert!(blocked(&rs, "/bun.lockb"));
        assert!(blocked(&rs, "/wp-login.php"));
        assert!(blocked(&rs, "/.yarnrc.yml"));
        assert!(blocked(&rs, "/bunfig.toml"));

        assert!(allowed(&rs, "/app/.env.staging"));
        assert!(allowed(&rs, "/frontend/package-lock.json"));
        assert!(allowed(&rs, "/frontend/bun.lock"));
        assert!(allowed(&rs, "/legacy/bun.lockb"));
        assert!(allowed(&rs, "/blog/wp-login.php"));
        assert!(allowed(&rs, "/frontend/.yarnrc.yml"));
        assert!(allowed(&rs, "/frontend/bunfig.toml"));
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
        assert!(allowed(&rs, "/docs/installation/guide"));
        assert!(allowed(&rs, "/users/administrator/profile"));
        assert!(allowed(&rs, "/tools/shell/docs"));
        assert!(allowed(&rs, "/downloads/downloader/guide"));
        assert!(allowed(&rs, "/"));
    }

    #[test]
    fn agent_protocol_discovery_paths_are_allowed() {
        let rs = compiled();
        let public_paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/llms.txt",
            "/llms-full.txt",
            "/auth.md",
            "/openapi.json",
            "/.well-known/http-message-signatures-directory",
            "/.well-known/api-catalog",
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/tenant",
            "/.well-known/openid-configuration",
            "/tenant/.well-known/openid-configuration",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/mcp.json",
            "/.well-known/mcp",
            "/.well-known/mcp/server-card.json",
            "/.well-known/agent-skills/index.json",
            "/.well-known/agent-skills/search/SKILL.md",
            "/.well-known/agent-card.json",
            "/.well-known/jwks.json",
            "/.well-known/ucp",
            "/.well-known/acp.json",
            "/mcp",
            "/oauth2/token",
            "/agent/identity",
            "/checkout_sessions",
        ];

        for path in public_paths {
            assert!(allowed(&rs, path), "expected {path} to remain reachable");
        }

        #[cfg(feature = "regex")]
        assert!(blocked(&rs, "/.well-known/.env"));
    }
}
