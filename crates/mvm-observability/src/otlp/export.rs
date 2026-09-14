//! The export queue, the thread that drains it, and the guard that flushes it.
//!
//! The instrumented side only ever calls `try_send` on a bounded channel, so a
//! slow or unreachable collector costs dropped spans, never a stalled thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use mvm_http::blocking::Client;
use mvm_http::{HeaderValue, Url, header};

use super::config::OtlpConfig;
use super::encode::{ResourceInfo, encode_batch};
use super::record::SpanRecord;

/// Spans held while the export thread is busy. Beyond this they are dropped.
const QUEUE_CAPACITY: usize = 2048;
/// Spans per request. Bounds the body size a collector has to accept.
const MAX_BATCH: usize = 512;
/// How long a partial batch waits for company before it is sent anyway.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
/// Collector responses carry nothing the exporter reads.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// What crosses the queue.
pub(crate) enum Message {
    Span(Box<SpanRecord>),
    /// Wakes a thread idle in `recv_timeout` so shutdown need not wait out the
    /// flush interval.
    Shutdown,
}

/// The sending half, held by the layer. Cloning shares the drop counter.
#[derive(Clone)]
pub(crate) struct SpanQueue {
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}

impl SpanQueue {
    /// Offer a span without waiting. A full or closed queue drops it and
    /// counts the loss.
    pub(crate) fn offer(&self, span: SpanRecord) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.tx.try_send(Message::Span(Box::new(span)))
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A bounded queue and its receiving half.
pub(crate) fn span_queue(capacity: usize) -> (SpanQueue, Receiver<Message>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
    (
        SpanQueue {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        },
        rx,
    )
}

/// Flushes queued spans when dropped.
///
/// Dropping signals the export thread to send what is queued and waits for it
/// at most the configured request timeout, so an unreachable collector delays
/// process exit by a bounded amount rather than indefinitely.
///
/// `std::process::exit` does not run destructors: a path that exits that way
/// skips the flush, and spans still queued at that moment are lost.
#[must_use = "dropping the guard immediately stops export"]
pub struct ExportGuard {
    queue: SpanQueue,
    shutdown: Arc<AtomicBool>,
    done: Receiver<()>,
    wait: Duration,
}

impl std::fmt::Debug for ExportGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportGuard")
            .field("wait", &self.wait)
            .finish_non_exhaustive()
    }
}

impl Drop for ExportGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // A full queue means the thread is busy draining and will see the flag
        // at its next receive; the wake-up is only for an idle thread.
        let _ = self.queue.tx.try_send(Message::Shutdown);
        let _ = self.done.recv_timeout(self.wait);
        let dropped = self.queue.dropped();
        if dropped > 0 {
            eprintln!("otlp: {dropped} span(s) dropped because the export queue was full");
        }
    }
}

/// Where a finished batch goes.
pub(crate) trait BatchSink: Send + 'static {
    fn send(&mut self, body: Vec<u8>) -> Result<(), String>;
}

/// POSTs batches to the collector.
struct HttpSink {
    client: Client,
    endpoint: Url,
}

impl HttpSink {
    fn new(config: &OtlpConfig) -> Result<Self, String> {
        let mut headers = config.headers().clone();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let client = Client::builder()
            .timeout(config.timeout())
            .connect_timeout(config.timeout())
            .max_response_bytes(MAX_RESPONSE_BYTES)
            .default_headers(headers)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            endpoint: config.endpoint().clone(),
        })
    }
}

impl BatchSink for HttpSink {
    fn send(&mut self, body: Vec<u8>) -> Result<(), String> {
        let response = self
            .client
            .post(self.endpoint.as_str())
            .body(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("collector answered {status}"))
        }
    }
}

/// Start exporting to the configured collector.
///
/// Returns the queue the layer offers spans to and the guard that flushes it.
pub(crate) fn start(config: &OtlpConfig) -> std::io::Result<(SpanQueue, ExportGuard)> {
    let sink = HttpSink::new(config).map_err(std::io::Error::other)?;
    let worker = Worker {
        sink,
        resource: ResourceInfo::current(config.service_name()),
        endpoint: config.endpoint().to_string(),
    };
    start_with_sink(worker, QUEUE_CAPACITY, config.timeout())
}

/// Everything the export thread owns.
pub(crate) struct Worker<K> {
    pub(crate) sink: K,
    pub(crate) resource: ResourceInfo,
    /// For the failure report only; never carries header values.
    pub(crate) endpoint: String,
}

pub(crate) fn start_with_sink<K: BatchSink>(
    worker: Worker<K>,
    capacity: usize,
    wait: Duration,
) -> std::io::Result<(SpanQueue, ExportGuard)> {
    let (queue, rx) = span_queue(capacity);
    let shutdown = Arc::new(AtomicBool::new(false));
    let (done_tx, done) = std::sync::mpsc::channel();
    let thread_shutdown = Arc::clone(&shutdown);
    thread::Builder::new()
        .name("mvm-otlp-export".into())
        .spawn(move || {
            worker.run(&rx, &thread_shutdown);
            let _ = done_tx.send(());
        })?;
    let guard = ExportGuard {
        queue: queue.clone(),
        shutdown,
        done,
        wait,
    };
    Ok((queue, guard))
}

impl<K: BatchSink> Worker<K> {
    fn run(mut self, rx: &Receiver<Message>, shutdown: &AtomicBool) {
        let mut reporter = FailureReporter::default();
        let mut batch = Vec::with_capacity(MAX_BATCH);
        let mut deadline: Option<Instant> = None;
        loop {
            let wait = deadline.map_or(FLUSH_INTERVAL, |d| {
                d.saturating_duration_since(Instant::now())
            });
            match rx.recv_timeout(wait) {
                Ok(Message::Span(span)) => {
                    deadline.get_or_insert_with(|| Instant::now() + FLUSH_INTERVAL);
                    batch.push(*span);
                    if batch.len() >= MAX_BATCH {
                        self.flush(&mut batch, &mut reporter);
                        deadline = None;
                    }
                }
                Ok(Message::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    self.flush(&mut batch, &mut reporter);
                    deadline = None;
                }
            }
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
        }
        self.drain(rx, &mut batch, &mut reporter);
    }

    /// Send what is already queued, without waiting for more. Bounded by the
    /// queue capacity so producers that keep emitting cannot hold it open.
    fn drain(
        &mut self,
        rx: &Receiver<Message>,
        batch: &mut Vec<SpanRecord>,
        reporter: &mut FailureReporter,
    ) {
        let spans = rx.try_iter().take(QUEUE_CAPACITY).filter_map(|m| match m {
            Message::Span(span) => Some(*span),
            Message::Shutdown => None,
        });
        for span in spans {
            batch.push(span);
            if batch.len() >= MAX_BATCH {
                self.flush(batch, reporter);
            }
        }
        self.flush(batch, reporter);
    }

    fn flush(&mut self, batch: &mut Vec<SpanRecord>, reporter: &mut FailureReporter) {
        if batch.is_empty() {
            return;
        }
        let body = encode_batch(&self.resource, batch);
        let count = batch.len();
        batch.clear();
        if let Err(error) = self.sink.send(body) {
            reporter.report(&self.endpoint, count, &error);
        }
    }
}

/// Reports the first failed export and stays silent after: a collector that is
/// down stays down for many batches, and a line per batch would bury the
/// command's own output.
#[derive(Default)]
struct FailureReporter {
    reported: bool,
}

impl FailureReporter {
    fn report(&mut self, endpoint: &str, spans: usize, error: &str) {
        if let Some(line) = self.first_failure_line(endpoint, spans, error) {
            eprintln!("{line}");
        }
    }

    fn first_failure_line(&mut self, endpoint: &str, spans: usize, error: &str) -> Option<String> {
        if std::mem::replace(&mut self.reported, true) {
            return None;
        }
        Some(format!(
            "otlp: export to {endpoint} failed, {spans} span(s) dropped: {error} \
             (further failures are not reported)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::SystemTime;

    fn span(id: u64) -> SpanRecord {
        SpanRecord {
            trace_id: 1,
            span_id: id,
            parent_span_id: None,
            name: format!("span-{id}"),
            start: SystemTime::UNIX_EPOCH,
            end: SystemTime::UNIX_EPOCH,
            attributes: Vec::new(),
            events: Vec::new(),
            error: false,
        }
    }

    /// Records the span count of each body it receives.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<usize>>>);

    impl BatchSink for Capture {
        fn send(&mut self, body: Vec<u8>) -> Result<(), String> {
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let spans = value["resourceSpans"][0]["scopeSpans"][0]["spans"]
                .as_array()
                .unwrap()
                .len();
            self.0.lock().unwrap().push(spans);
            Ok(())
        }
    }

    fn worker(sink: Capture) -> Worker<Capture> {
        Worker {
            sink,
            resource: ResourceInfo::current("test"),
            endpoint: "https://collector.example.com/v1/traces".into(),
        }
    }

    #[test]
    fn a_full_queue_drops_the_span_and_counts_it_without_blocking() {
        let (queue, _rx) = span_queue(1);
        let started = Instant::now();
        queue.offer(span(1));
        queue.offer(span(2));
        queue.offer(span(3));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(queue.dropped(), 2);
    }

    #[test]
    fn dropping_the_guard_flushes_queued_spans_in_bounded_batches() {
        let sink = Capture::default();
        let (queue, guard) =
            start_with_sink(worker(sink.clone()), 4096, Duration::from_secs(5)).unwrap();
        for id in 1..=(MAX_BATCH as u64 + 10) {
            queue.offer(span(id));
        }
        drop(guard);
        let batches = sink.0.lock().unwrap().clone();
        assert_eq!(batches.iter().sum::<usize>(), MAX_BATCH + 10);
        assert!(batches.iter().all(|&n| n <= MAX_BATCH), "{batches:?}");
        assert_eq!(queue.dropped(), 0);
    }

    #[test]
    fn only_the_first_export_failure_is_reported() {
        let mut reporter = FailureReporter::default();
        let first = reporter
            .first_failure_line("https://c.example.com/v1/traces", 3, "refused")
            .unwrap();
        assert!(first.contains("https://c.example.com/v1/traces"));
        assert!(first.contains("3 span(s)"));
        assert!(first.contains("refused"));
        assert!(reporter.first_failure_line("x", 1, "again").is_none());
    }
}
