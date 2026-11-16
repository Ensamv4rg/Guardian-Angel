//! Live DNS monitoring through the Microsoft-Windows-DNS-Client ETW provider.
//!
//! Event 3008 ("query completed") is logged in the context of the program
//! that made the lookup, so its process ID identifies who looked up what.
//! The other events from this provider come from the DNS service itself.

use crate::aggregator::Aggregator;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{TraceError, UserTrace, stop_trace_by_name};
use ga_core::NetworkCapture;
use std::sync::{Arc, Mutex, MutexGuard};

const SESSION_NAME: &str = "GuardianAngel-DNS";
const DNS_CLIENT_PROVIDER: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const QUERY_COMPLETED: u16 = 3008;

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

#[derive(Debug, thiserror::Error)]
pub enum NetmonError {
    #[error(
        "Windows refused to start the trace. Run as administrator, or add your account \
         to the 'Performance Log Users' group."
    )]
    AccessDenied,
    #[error("Could not start the DNS trace: {0}")]
    Start(String),
}

/// A running DNS trace. Stops automatically when dropped.
pub struct DnsMonitor {
    trace: Option<UserTrace>,
    aggregator: Arc<Mutex<Aggregator>>,
}

impl DnsMonitor {
    pub fn start() -> Result<Self, NetmonError> {
        let aggregator = Arc::new(Mutex::new(Aggregator::new(
            std::process::id(),
            unix_now(),
            Box::new(ga_platform_win::process_image_path),
        )));

        let trace = match start_trace(aggregator.clone()) {
            // A previous run crashed and left its session behind: clear it once.
            Err(TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)) => {
                let _ = stop_trace_by_name(SESSION_NAME);
                start_trace(aggregator.clone())
            }
            other => other,
        }
        .map_err(map_error)?;

        Ok(Self {
            trace: Some(trace),
            aggregator,
        })
    }

    /// Totals so far, without stopping.
    pub fn snapshot(&self) -> NetworkCapture {
        lock(&self.aggregator).snapshot(unix_now())
    }

    /// Stops the trace and returns the final totals.
    pub fn stop(mut self) -> NetworkCapture {
        if let Some(trace) = self.trace.take() {
            let _ = trace.stop();
        }
        self.snapshot()
    }
}

fn start_trace(aggregator: Arc<Mutex<Aggregator>>) -> Result<UserTrace, TraceError> {
    let provider = Provider::by_guid(DNS_CLIENT_PROVIDER)
        .add_callback(move |record, locator| {
            if record.event_id() != QUERY_COMPLETED {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else { return };
            let parser = Parser::create(record, &schema);
            let Ok(name) = parser.try_parse::<String>("QueryName") else { return };
            let status: u32 = parser.try_parse("QueryStatus").unwrap_or(0);
            let unix = record.raw_timestamp() / 10_000_000 - FILETIME_EPOCH_OFFSET_SECS;
            lock(&aggregator).record(record.process_id(), &name, status == 0, unix);
        })
        .build();

    UserTrace::new()
        .named(SESSION_NAME.to_owned())
        .enable(provider)
        .start_and_process()
}

fn map_error(err: TraceError) -> NetmonError {
    match err {
        TraceError::EtwNativeError(EvntraceNativeError::IoError(io))
            if io.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            NetmonError::AccessDenied
        }
        other => NetmonError::Start(format!("{other:?}")),
    }
}

/// A panic in one callback must not stop all future monitoring.
fn lock(m: &Mutex<Aggregator>) -> MutexGuard<'_, Aggregator> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
