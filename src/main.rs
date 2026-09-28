//! `ais_domains` -- domain and SSL management for the Artisan Hosting platform.
//!
//! Replaces three manual tools that used to live in this directory (now under
//! `legacy/`): the `certs` acme.sh wrapper, the `issuer` publish script, and
//! the publishing half of `nginx-r2-agent`. The edge half of that agent stays
//! exactly where it is -- this service publishes to R2 in the layout it
//! already reads.
//!
//! Run it as a service (`serve`), or reach for the same code paths by hand
//! the way the old scripts were run: `issue <domain>`, `publish`, `import`.

use ais_domains::{acme, auth, cloudflare, config, db, error, grpc, inventory, publish, vhost};
use artisan_middleware::dusa_collection_utils::core::logger::{LogLevel, set_log_level};
use artisan_middleware::dusa_collection_utils::log;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use self::config::{Config, Secrets};
use self::error::Result;

#[derive(Parser, Debug)]
#[command(
    name = "ais_domains",
    version,
    about = "Artisan Hosting domain + SSL management"
)]
struct Cli {
    /// Defaults to /opt/artisan/etc/ais_domains.json.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Credentials file. Defaults to /opt/artisan/etc/ais_domains.env.
    #[arg(long, global = true, value_name = "PATH")]
    env_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the gRPC service and its background workers (the default).
    Serve,

    /// Apply pending database migrations and exit.
    Migrate,

    /// Read everything that already exists -- the domain list, the nginx
    /// tree, the certificates on disk -- and write an inventory plus a plan
    /// file to review. Read-only: safe to run against production at any time.
    Scan {
        /// One domain per line, `#` comments allowed -- the file the `certs`
        /// script read.
        #[arg(long, default_value = "/etc/acme-sh/domains.txt")]
        domains_file: PathBuf,

        /// Facts: what exists and what is wrong with it.
        #[arg(long, default_value = "inventory.json")]
        inventory_out: PathBuf,

        /// Decisions: the file you edit, then feed to `apply`.
        #[arg(long, default_value = "plan.json")]
        plan_out: PathBuf,

        /// Resolve each domain and check its records against the edge.
        #[arg(long)]
        check_dns: bool,

        /// Ask Cloudflare whether we already hold a zone for each domain.
        #[arg(long)]
        check_cloudflare: bool,

        /// Portal base URL, for repo names. Without it, suggestions can only
        /// match runner ids, which no domain name contains.
        #[arg(long)]
        portal_url: Option<String>,

        /// Log in to ais_auth as this email to fetch organizations and runners.
        #[arg(long)]
        login: Option<String>,

        /// An existing access token, instead of logging in.
        #[arg(long, env = "ARTISAN_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },

    /// Summarize a plan file without applying it.
    Plan {
        #[command(subcommand)]
        command: PlanCommand,
    },

    /// Apply a reviewed plan: record domains, adopt vhosts, carry findings
    /// over. Idempotent -- running it twice changes nothing the second time.
    Apply {
        #[arg(default_value = "plan.json")]
        file: PathBuf,

        /// Work out every change and print it, write nothing.
        #[arg(long)]
        dry_run: bool,

        /// Allow moving a domain that already belongs to an organization.
        #[arg(long)]
        force_reassign: bool,

        #[arg(long)]
        login: Option<String>,

        #[arg(long, env = "ARTISAN_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },

    /// Move confirmed quarantine entries out of the tree and into the attic.
    /// Nothing is deleted, and the whole run rolls back if nginx then
    /// rejects the tree.
    Clean {
        #[arg(default_value = "plan.json")]
        file: PathBuf,

        /// Actually move things. Without it, this only reports.
        #[arg(long)]
        fix: bool,
    },

    /// Issue (or renew) one domain's certificate pair, the by-hand
    /// equivalent of running the old `certs` script for a single name.
    Issue {
        domain: String,

        /// Issue even if the current certificate is not near expiry.
        #[arg(long)]
        force: bool,
    },

    /// Stage the nginx tree, test it, and publish a release to R2.
    Publish {
        /// Stage and run `nginx -t`, but upload nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PlanCommand {
    /// Print what a plan file would do.
    Show {
        #[arg(default_value = "plan.json")]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    // The dependency tree pulls in both rustls crypto backends (tonic/sqlx
    // want ring, reqwest/rcgen/aws-sdk-s3 want aws-lc-rs), so rustls can't
    // auto-pick a process-wide default and panics on first use without this.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    set_log_level(LogLevel::Info);

    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        log!(LogLevel::Error, "{}", err);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config = Config::load(cli.config.as_deref())?;
    let secrets = Secrets::load(cli.env_file.as_deref())?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config, secrets).await,
        Command::Migrate => {
            let pool = db::connect(&secrets.database_url).await?;
            db::migrate(&pool).await?;
            log!(LogLevel::Info, "migrations applied");
            Ok(())
        }
        Command::Scan {
            domains_file,
            inventory_out,
            plan_out,
            check_dns,
            check_cloudflare,
            portal_url,
            login,
            token,
        } => {
            scan_command(
                config,
                secrets,
                ScanArgs {
                    domains_file,
                    inventory_out,
                    plan_out,
                    check_dns,
                    check_cloudflare,
                    portal_url,
                    login,
                    token,
                },
            )
            .await
        }
        Command::Plan { command } => match command {
            PlanCommand::Show { file } => {
                let plan = read_plan(&file)?;
                println!("{}", plan.summary());
                Ok(())
            }
        },
        Command::Apply { file, dry_run, force_reassign, login, token } => {
            apply_command(config, secrets, file, dry_run, force_reassign, login, token).await
        }
        Command::Clean { file, fix } => {
            let plan = read_plan(&file)?;
            let report = inventory::attic::quarantine(&config, &plan, !fix).await?;

            for entry in &report.moved {
                log!(LogLevel::Info, "  {} ({})", entry.path, entry.reason);
            }
            for skipped in &report.skipped {
                log!(LogLevel::Info, "  skipped {}", skipped);
            }
            if !fix {
                log!(LogLevel::Info, "report only -- pass --fix to move anything");
            }
            log!(LogLevel::Info, "{}", report.summary());
            Ok(())
        }
        Command::Issue { domain, force } => issue_one(config, secrets, &domain, force).await,
        Command::Publish { dry_run } => {
            let outcome = publish::publish(&config, &secrets, dry_run).await?;
            log!(
                LogLevel::Info,
                "release {} staged with {} file(s){}",
                outcome.release_id,
                outcome.file_count,
                if outcome.published { ", published" } else { ", not published" }
            );
            Ok(())
        }
    }
}

struct ScanArgs {
    domains_file: PathBuf,
    inventory_out: PathBuf,
    plan_out: PathBuf,
    check_dns: bool,
    check_cloudflare: bool,
    portal_url: Option<String>,
    login: Option<String>,
    token: Option<String>,
}

/// Look at everything, decide nothing.
async fn scan_command(config: Config, secrets: Secrets, args: ScanArgs) -> Result<()> {
    let options = inventory::scan::ScanOptions {
        domains_file: args.domains_file,
        check_dns: args.check_dns,
        check_cloudflare: args.check_cloudflare,
    };

    let inventory_data = inventory::scan::run(&config, &secrets, &options).await?;

    // The catalog is what makes suggestions possible. Not having it is a
    // weaker scan, never a failed one -- ais_auth being down should not stop
    // anyone finding out what is on their own disk.
    let catalog = match credentials(&config, args.token, args.login, false).await {
        Ok(Some((client, creds))) => {
            let mut catalog = client.catalog(&creds.access_token).await.unwrap_or_else(|err| {
                log!(LogLevel::Warn, "could not read organizations from ais_auth: {}", err);
                Default::default()
            });

            if let Some(portal_url) = &args.portal_url {
                match auth::enrich_from_portal(&mut catalog, portal_url, &creds.access_token).await {
                    Ok(count) => log!(LogLevel::Info, "matched {count} repo name(s) from Portal"),
                    Err(err) => log!(LogLevel::Warn, "Portal repo catalog unavailable: {}", err),
                }
            }

            log!(
                LogLevel::Info,
                "catalog: {} organization(s), {} runner(s)",
                catalog.organizations.len(),
                catalog.runners.len()
            );
            catalog
        }
        Ok(None) => {
            log!(
                LogLevel::Warn,
                "no ais_auth credentials given (--login or --token); the plan will have nothing to suggest"
            );
            Default::default()
        }
        Err(err) => {
            log!(LogLevel::Warn, "ais_auth login failed ({}); continuing without a catalog", err);
            Default::default()
        }
    };

    let plan = inventory::plan::from_inventory(&inventory_data, catalog);

    write_json(&args.inventory_out, &serde_json::to_string_pretty(&inventory_data).map_err(|e| {
        error::Error::Invalid(format!("serializing inventory: {e}"))
    })?)?;
    write_json(&args.plan_out, &plan.to_json()?)?;

    log!(LogLevel::Info, "wrote {} and {}", args.inventory_out.display(), args.plan_out.display());
    println!("{}", plan.summary());
    println!("\nEdit {} -- set `assign` per domain, tick any quarantine you want -- then run:\n  ais_domains apply {} --dry-run", args.plan_out.display(), args.plan_out.display());

    Ok(())
}

async fn apply_command(
    config: Config,
    secrets: Secrets,
    file: PathBuf,
    dry_run: bool,
    force_reassign: bool,
    login: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let plan = read_plan(&file)?;

    // Only ask for a password when something in the plan actually needs one.
    let needs_elevation = plan.runner_org_assignments.iter().any(|a| a.apply);
    let auth_pair = credentials(&config, token, login, needs_elevation).await?;

    let pool = db::connect(&secrets.database_url).await?;
    db::migrate(&pool).await?;

    let options = inventory::apply::ApplyOptions { dry_run, force_reassign };
    let report = inventory::apply::apply(
        &pool,
        &config,
        &plan,
        auth_pair.as_ref().map(|(client, creds)| (client, creds)),
        &options,
    )
    .await?;

    inventory::apply::log_report(&report, dry_run);
    Ok(())
}

fn read_plan(path: &PathBuf) -> Result<inventory::plan::Plan> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| error::Error::Invalid(format!("reading {}: {e}", path.display())))?;
    inventory::plan::Plan::load(&raw)
}

fn write_json(path: &PathBuf, contents: &str) -> Result<()> {
    std::fs::write(path, contents)
        .map_err(|e| error::Error::Invalid(format!("writing {}: {e}", path.display())))
}

/// Works out how to talk to ais_auth, asking for as little as possible.
///
/// A token alone is enough to read; anything that writes to ais_auth's own
/// tables costs a password, every run, because that is what `ElevateSession`
/// is for.
async fn credentials(
    config: &Config,
    token: Option<String>,
    login: Option<String>,
    need_elevated: bool,
) -> Result<Option<(auth::AuthClient, auth::Credentials)>> {
    let client = auth::AuthClient::new(&config.auth.grpc_addr)?;

    let mut creds = match (token, &login) {
        (Some(token), _) => auth::Credentials { access_token: token, elevated_token: None },
        (None, Some(email)) => {
            let password = auth::prompt_password(&format!("ais_auth password for {email}: "))?;
            client.login(email, &password).await?
        }
        (None, None) => return Ok(None),
    };

    if need_elevated {
        let who = login.as_deref().unwrap_or("your account");
        let password = auth::prompt_password(&format!(
            "password for {who} again (writing to ais_auth needs an elevated token): "
        ))?;
        creds.elevated_token = Some(client.elevate(&creds.access_token, &password).await?);
    }

    Ok(Some((client, creds)))
}

/// The by-hand issuance path: what running the old `certs` script for a
/// single domain did, without the database or the job queue in the way.
///
/// Deliberately available as a subcommand -- when something is wrong at 3am,
/// being able to issue one certificate without a working database is worth
/// more than tidiness.
async fn issue_one(config: Config, secrets: Secrets, domain: &str, force: bool) -> Result<()> {
    secrets.require(&[
        ("CF_CHALLENGE_TOKEN", &secrets.cf_challenge_token),
    ])?;

    if config.acme.alias_zone_id.is_empty() {
        return Err(error::Error::Config(
            "acme.alias_zone_id is not set; challenge records have nowhere to go".to_owned(),
        ));
    }

    // Skip the work if the certificate on disk is still good, unless told
    // otherwise. Let's Encrypt's rate limits are per registered domain per
    // week, and a renewal loop that ignores them locks everyone out.
    if !force {
        if let Some(not_after) = acme::install::read_expiry(&config, domain, acme::KeyType::Ecc)? {
            let days_left = (not_after - chrono::Utc::now().timestamp()) / 86_400;
            if days_left > config.acme.renew_before_days {
                log!(
                    LogLevel::Info,
                    "{domain}: certificate still valid for {days_left} day(s); use --force to issue anyway"
                );
                return Ok(());
            }
        }
    }

    let cf = cloudflare::CfSuite::new(&config, &secrets)?;
    let challenge_target = config.challenge_target_for(domain);

    let account = acme::account::load_or_create(&config).await?;
    let issuer = acme::issue::Issuer::new(config.clone(), cf)?;

    let certs = issuer.issue_pair(&account, domain, &challenge_target).await?;
    acme::install::write_pair(&config, domain, &certs)?;

    log!(
        LogLevel::Info,
        "{domain}: issued {} certificate(s) into {}",
        certs.len(),
        config.cert_dir_for(domain).display()
    );

    // The step that used to be manual: without a snippet linking the pair,
    // the certificate renews forever and nothing serves it.
    match vhost::snippet::ensure(&config, domain)? {
        vhost::snippet::SnippetOutcome::Created(path) => {
            log!(LogLevel::Info, "{domain}: wrote {}", path.display());
            log!(
                LogLevel::Info,
                "{domain}: include it from the vhost with `include {}/{}_cert.conf;`",
                config.tree.snippets_dir,
                config::snippet_slug(domain)
            );
        }
        vhost::snippet::SnippetOutcome::Updated(path) => {
            log!(LogLevel::Info, "{domain}: updated {}", path.display())
        }
        vhost::snippet::SnippetOutcome::Unchanged(path) => {
            log!(LogLevel::Trace, "{domain}: {} already current", path.display())
        }
        vhost::snippet::SnippetOutcome::HandWritten { path, .. } => log!(
            LogLevel::Warn,
            "{domain}: {} was written by hand and has been left alone -- check it points at this certificate",
            path.display()
        ),
    }

    Ok(())
}

async fn serve(config: Config, secrets: Secrets) -> Result<()> {
    secrets.require(&[("DATABASE_URL", &secrets.database_url)])?;

    let pool = db::connect(&secrets.database_url).await?;
    db::migrate(&pool).await?;
    log!(LogLevel::Info, "database ready");

    grpc::serve(config, secrets, pool).await
}
