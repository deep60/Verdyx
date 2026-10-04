//! OpenTelemetry distributed tracing integration
//!
//! Provides unified tracing setup with OTLP export to Tempo/Jaeger/Grafana

#[cfg(feature = "otel")]
use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
#[cfg(feature = "otel")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "otel")]
use opentelemetry_sdk::trace::{self, RandomIdGenerator, Sampler, Runtime};
#[cfg(feature = "otel")]
use opentelemetry_sdk::Resource;
#[cfg(feature = "otel")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(feature = "otel")]
use tracing_subscriber::{layer::SubscriberExt, Registry, Layer, util::SubscriberInitExt};

use super::{ObservabilityError, ObservabilityResult};

/// OpenTelemetry configuration
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Service name (used as resource attribute)
    pub service_name: String,
    /// OTLP endpoint (e.g., "http://tempo:4317" or "https://tempo.example.com:4317")
    pub otlp_endpoint: String,
    /// Sampling rate (0.0 to 1.0)
    pub sample_rate: f64,
    /// Whether to use TLS (for OTLP/HTTP)
    pub tls: bool,
    /// Additional resource attributes
    pub attributes: Vec<(String, String)>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            service_name: "verdyx-service".to_string(),
            otlp_endpoint: "http://localhost:4317".to_string(),
            sample_rate: 1.0,
            tls: false,
            attributes: vec![
                ("deployment.environment".to_string(), std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string())),
                ("service.version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ],
        }
    }
}

/// Global tracer provider storage
#[cfg(feature = "otel")]
static GLOBAL_TRACER_PROVIDER: std::sync::OnceLock<opentelemetry_sdk::trace::TracerProvider> = std::sync::OnceLock::new();

/// Initialize OpenTelemetry tracing
#[cfg(feature = "otel")]
pub fn init_otel_tracing(config: OtelConfig) -> ObservabilityResult<()> {
    // Build resource with service info
    let mut resource_attrs = vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ];
    
    for (k, v) in config.attributes {
        resource_attrs.push(KeyValue::new(k, v));
    }
    
    let resource = Resource::new(resource_attrs);

    // Configure OTLP exporter
    let mut exporter_builder = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(config.otlp_endpoint);
    
    if config.tls {
        // For TLS, you'd configure the tonic transport with TLS config
        // This is a simplified version - in production you'd load certs
    }

    // Create tracer provider with batch exporter
    let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
        .with_id_generator(RandomIdGenerator::default())
        .with_batch_exporter(
            exporter_builder.build().map_err(|e| ObservabilityError::Tracing(e.to_string()))?,
            Runtime::TokioCurrentThread
        )
        .build();

    // Store the tracer provider globally for later use
    GLOBAL_TRACER_PROVIDER.set(tracer_provider.clone())
        .map_err(|_| ObservabilityError::Tracing("Tracer provider already initialized".to_string()))?;

    // Create the OpenTelemetry layer for tracing-subscriber
    let tracer = tracer_provider.tracer(config.service_name.clone());
    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Set global tracer provider
    global::set_tracer_provider(GLOBAL_TRACER_PROVIDER.get().unwrap().clone());

    // Install the layer - note: this requires the caller to add it to their subscriber
    // We return the layer so the caller can compose it with their logging layer
    // For now, we'll just initialize the global provider
    
    tracing::info!(
        service = %config.service_name,
        endpoint = %config.otlp_endpoint,
        sample_rate = config.sample_rate,
        "OpenTelemetry tracing initialized"
    );

    Ok(())
}

/// Initialize OpenTelemetry with a combined subscriber (logging + tracing + OTel)
#[cfg(feature = "otel")]
pub fn init_combined_subscriber(
    log_config: super::logging::LogConfig,
    otel_config: OtelConfig,
) -> ObservabilityResult<()> {
    // Initialize OTel first
    init_otel_tracing(otel_config.clone())?;

    // Get the SDK tracer provider from the global storage
    let sdk_provider = GLOBAL_TRACER_PROVIDER.get()
        .ok_or_else(|| ObservabilityError::Tracing("Tracer provider not initialized".to_string()))?;
    
    let tracer = sdk_provider.tracer(otel_config.service_name.clone());
    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Create the logging layer based on config
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_config.level.as_str()));

    let fmt_layer = match log_config.format {
        super::logging::LogFormat::Pretty => {
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(log_config.include_thread_ids)
                .with_line_number(log_config.include_line_numbers)
                .pretty()
                .boxed()
        }
        super::logging::LogFormat::Json => {
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_current_span(true)
                .with_thread_ids(log_config.include_thread_ids)
                .with_line_number(log_config.include_line_numbers)
                .boxed()
        }
        super::logging::LogFormat::Compact => {
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(log_config.include_thread_ids)
                .boxed()
        }
    };

    // Combine all layers
    Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .map_err(|e| ObservabilityError::Logging(e.to_string()))?;

    tracing::info!(
        service = %log_config.service_name,
        "Combined subscriber initialized (logging + OpenTelemetry)"
    );

    Ok(())
}

/// Shutdown OpenTelemetry gracefully
#[cfg(feature = "otel")]
pub fn shutdown_otel() {
    if let Some(provider) = GLOBAL_TRACER_PROVIDER.get() {
        // Force flush any pending spans
        let _ = provider.force_flush();
    }
    global::shutdown_tracer_provider();
    tracing::info!("OpenTelemetry tracer provider shut down");
}

/// Helper to get the current span's trace context for propagation
#[cfg(feature = "otel")]
pub fn current_trace_context() -> Vec<(String, String)> {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    
    let span = tracing::Span::current();
    let otel_ctx = span.context();
    let span_ref = otel_ctx.span();
    let span_ctx = span_ref.span_context();
    let trace_id = span_ctx.trace_id();
    let span_id = span_ctx.span_id();
    
    vec![
        ("traceparent".to_string(), format!("00-{:032x}-{:016x}-01", trace_id, span_id)),
    ]
}

/// Extract trace context from headers (for incoming requests)
#[cfg(feature = "otel")]
pub fn extract_trace_context(headers: &std::collections::HashMap<String, String>) -> Option<opentelemetry::Context> {
    use opentelemetry::trace::TraceContextExt;
    use opentelemetry::propagation::Extractor;
    
    struct HeaderExtractor<'a>(&'a std::collections::HashMap<String, String>);
    
    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).map(|s| s.as_str())
        }
        
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|s| s.as_str()).collect()
        }
    }
    
    let extractor = HeaderExtractor(headers);
    let propagator = opentelemetry::global::text_map_propagator();
    Some(propagator.extract(&extractor))
}