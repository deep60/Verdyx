//! Application metrics collection and reporting

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Simple metrics collector
pub struct MetricsCollector {
    counters: Arc<RwLock<HashMap<String, AtomicU64>>>,
    gauges: Arc<RwLock<HashMap<String, AtomicU64>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Increment a counter
    pub fn increment_counter(&self, name: &str, value: u64) {
        let counters = self.counters.read().unwrap();
        if let Some(counter) = counters.get(name) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            drop(counters);
            let mut counters = self.counters.write().unwrap();
            counters.insert(name.to_string(), AtomicU64::new(value));
        }
    }

    /// Set a gauge value
    pub fn set_gauge(&self, name: &str, value: u64) {
        let gauges = self.gauges.read().unwrap();
        if let Some(gauge) = gauges.get(name) {
            gauge.store(value, Ordering::Relaxed);
        } else {
            drop(gauges);
            let mut gauges = self.gauges.write().unwrap();
            gauges.insert(name.to_string(), AtomicU64::new(value));
        }
    }

    /// Get counter value
    pub fn get_counter(&self, name: &str) -> Option<u64> {
        self.counters
            .read()
            .unwrap()
            .get(name)
            .map(|counter| counter.load(Ordering::Relaxed))
    }

    /// Get gauge value
    pub fn get_gauge(&self, name: &str) -> Option<u64> {
        self.gauges
            .read()
            .unwrap()
            .get(name)
            .map(|gauge| gauge.load(Ordering::Relaxed))
    }

    /// Get all metrics as a snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        let counters: HashMap<String, u64> = self
            .counters
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let gauges: HashMap<String, u64> = self
            .gauges
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        MetricsSnapshot { counters, gauges }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub counters: HashMap<String, u64>,
    pub gauges: HashMap<String, u64>,
}

/// Common metric names
pub mod metric_names {
    // HTTP metrics
    pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
    pub const HTTP_REQUESTS_DURATION_MS: &str = "http_requests_duration_ms";
    pub const HTTP_REQUESTS_ERROR: &str = "http_requests_error";

    // Database metrics
    pub const DB_QUERIES_TOTAL: &str = "db_queries_total";
    pub const DB_QUERIES_DURATION_MS: &str = "db_queries_duration_ms";
    pub const DB_CONNECTIONS_ACTIVE: &str = "db_connections_active";

    // Cache metrics
    pub const CACHE_HITS: &str = "cache_hits";
    pub const CACHE_MISSES: &str = "cache_misses";

    // Business metrics
    pub const USERS_TOTAL: &str = "users_total";
    pub const BOUNTIES_TOTAL: &str = "bounties_total";
    pub const ANALYSES_TOTAL: &str = "analyses_total";
    pub const SUBMISSIONS_TOTAL: &str = "submissions_total";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let metrics = MetricsCollector::new();

        metrics.increment_counter("test_counter", 1);
        assert_eq!(metrics.get_counter("test_counter"), Some(1));

        metrics.increment_counter("test_counter", 5);
        assert_eq!(metrics.get_counter("test_counter"), Some(6));
    }

    #[test]
    fn test_gauge() {
        let metrics = MetricsCollector::new();

        metrics.set_gauge("test_gauge", 100);
        assert_eq!(metrics.get_gauge("test_gauge"), Some(100));

        metrics.set_gauge("test_gauge", 50);
        assert_eq!(metrics.get_gauge("test_gauge"), Some(50));
    }

    #[test]
    fn test_snapshot() {
        let metrics = MetricsCollector::new();

        metrics.increment_counter("counter1", 10);
        metrics.set_gauge("gauge1", 42);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.counters.get("counter1"), Some(&10));
        assert_eq!(snapshot.gauges.get("gauge1"), Some(&42));
    }
}
