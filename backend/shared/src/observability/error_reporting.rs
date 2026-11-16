//! Error reporting to Sentry.
//!
//! Off unless `SENTRY_DSN` is set, so local runs and tests send nothing. When
//! on, each service reports:
//!
//! - `tracing::error!` events, as Sentry issues;
//! - panics, with a backtrace;
//! - recent `warn!`/`info!` lines, attached to the next issue as breadcrumbs.
//!
//! It sends no performance traces (keeping within the free quota) and no
//! personal data: no IP addresses, cookies or request bodies.
//!
//! Usage, at the top of `main`:
//!
//! ```ignore
//! let _sentry = shared::observability::error_reporting::init("api-gateway", env!("CARGO_PKG_VERSION"));
//! tracing_subscriber::fmt()/* ...as before... */
//!     .finish()
//!     .with(shared::observability::error_reporting::layer())
//!     .init();
//! ```
//!
//! Keep the returned guard alive for the life of the process: dropping it
//! flushes queued events and stops reporting.

use tracing::Level;
use tracing_subscriber::Layer;

/// Holds the Sentry client open. Dropping it flushes pending events.
#[must_use = "dropping the guard stops error reporting"]
pub struct ErrorReporting {
    _guard: Option<sentry::ClientInitGuard>,
}

impl ErrorReporting {
    pub fn is_enabled(&self) -> bool {
        self._guard.as_ref().is_some_and(|g| g.is_enabled())
    }
}

/// The DSN to report to, if one is configured.
fn dsn_from_env() -> Option<String> {
    std::env::var("SENTRY_DSN")
        .ok()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
}

/// `SENTRY_ENVIRONMENT`, else `ENVIRONMENT`, else "production".
fn environment_from_env() -> String {
    ["SENTRY_ENVIRONMENT", "ENVIRONMENT"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| "production".to_string())
}

/// Start reporting for `service` at `version`, if `SENTRY_DSN` is set.
pub fn init(service: &'static str, version: &'static str) -> ErrorReporting {
    let Some(dsn) = dsn_from_env() else {
        return ErrorReporting { _guard: None };
    };
    let dsn = match dsn.parse() {
        Ok(d) => Some(d),
        Err(e) => {
            // Logged on stderr: tracing isn't set up yet.
            eprintln!("SENTRY_DSN is not a valid DSN, error reporting is off: {e}");
            return ErrorReporting { _guard: None };
        }
    };
    // Performance tracing stays at its default of off.
    let mut options = sentry::ClientOptions::default();
    options.dsn = dsn;
    options.release = Some(format!("{service}@{version}").into());
    options.environment = Some(environment_from_env().into());
    options.send_default_pii = false;
    options.attach_stacktrace = true;
    let guard = sentry::init(options);
    sentry::configure_scope(|scope| scope.set_tag("service", service));
    ErrorReporting {
        _guard: Some(guard),
    }
}

/// What each log level becomes in Sentry.
fn filter(level: &Level) -> sentry::integrations::tracing::EventFilter {
    use sentry::integrations::tracing::EventFilter;
    match *level {
        Level::ERROR => EventFilter::Event,
        Level::WARN | Level::INFO => EventFilter::Breadcrumb,
        _ => EventFilter::Ignore,
    }
}

/// The tracing layer that forwards logs to Sentry. Harmless when reporting is
/// off: with no client, it records nothing.
pub fn layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    sentry::integrations::tracing::layer().event_filter(|md| filter(md.level()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry::integrations::tracing::EventFilter;

    #[test]
    fn errors_become_issues_and_info_breadcrumbs() {
        // EventFilter is a set of flags without PartialEq; compare the bits.
        let is = |l: Level, f: EventFilter| filter(&l).bits() == f.bits();
        assert!(is(Level::ERROR, EventFilter::Event));
        assert!(is(Level::WARN, EventFilter::Breadcrumb));
        assert!(is(Level::INFO, EventFilter::Breadcrumb));
        assert!(is(Level::DEBUG, EventFilter::Ignore));
    }

    #[test]
    fn errors_reach_sentry_through_the_layer() {
        use tracing_subscriber::layer::SubscriberExt;

        let events = sentry::test::with_captured_events(|| {
            let subscriber = tracing_subscriber::registry().with(layer());
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!("routine line");
                tracing::error!("database unreachable");
            });
        });
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.message.as_deref(), Some("database unreachable"));
        // The info line rode along as a breadcrumb.
        assert!(event
            .breadcrumbs
            .iter()
            .any(|b| b.message.as_deref() == Some("routine line")));
    }

    #[test]
    fn off_without_a_dsn() {
        // SAFETY of env mutation: this test only reads its own variable name
        // and runs in a test binary; no other test sets SENTRY_DSN.
        if std::env::var("SENTRY_DSN").is_ok() {
            return;
        }
        assert!(!init("test", "0.0.0").is_enabled());
    }
}
