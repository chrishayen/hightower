use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use kv::{KvEngine, SingleNodeEngine, StoreConfig};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn bench_engine_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_writes");
    for (label, key_len, value_len) in [("small", 16, 64), ("medium", 16, 512), ("large", 32, 4096)]
    {
        group.bench_with_input(
            BenchmarkId::new("put_1k", label),
            &(key_len, value_len),
            |b, &(k, v)| {
                b.iter_batched(
                    setup_engine,
                    |harness| {
                        let mut rng = StdRng::seed_from_u64(42);
                        for _ in 0..1024 {
                            harness
                                .engine
                                .put(random_key(&mut rng, k), random_value(&mut rng, v))
                                .unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_engine_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_reads");
    for (label, cold) in [("hot", false), ("cold", true)] {
        group.bench_function(BenchmarkId::new("get_4k", label), |b| {
            b.iter_batched(
                || prepare_dataset(4096, 16, 256, cold),
                |(harness, keys)| {
                    for key in keys {
                        let _ = harness.engine.get(&key).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_compaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("compaction");
    group.bench_function("run_compaction_now", |b| {
        b.iter_batched(
            || {
                let harness = setup_engine();
                let mut rng = StdRng::seed_from_u64(999);
                for i in 0..20_000 {
                    harness
                        .engine
                        .put(random_key(&mut rng, 16), random_value(&mut rng, 256))
                        .unwrap();
                    if i % 5 == 0 {
                        harness.engine.delete(random_key(&mut rng, 16)).unwrap();
                    }
                }
                harness
            },
            |harness| {
                harness.engine.run_compaction_now().unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_engine_writes_parallel(c: &mut Criterion) {
    const TOTAL_OPS: usize = 4096;
    let mut group = c.benchmark_group("engine_writes_parallel");
    for workers in [None, Some(1usize), Some(2), Some(4), Some(8)] {
        match workers {
            None => {
                group.bench_function(BenchmarkId::new("workers", "inline"), |b| {
                    b.iter_batched(
                        || setup_engine_with_workers(Some(0)),
                        |harness| {
                            let EngineHarness {
                                engine,
                                tempdir,
                                cfg,
                            } = harness;
                            let _keep_tempdir = tempdir;
                            let mut rng = StdRng::seed_from_u64(20_001);
                            for _ in 0..TOTAL_OPS {
                                let key = random_key(&mut rng, 32);
                                let value = random_value(&mut rng, 256);
                                engine.put(key, value).unwrap();
                            }
                            drop(cfg);
                        },
                        BatchSize::SmallInput,
                    );
                });
            }
            Some(worker_count) => {
                if TOTAL_OPS % worker_count != 0 {
                    continue;
                }
                group.bench_with_input(
                    BenchmarkId::from_parameter(worker_count),
                    &worker_count,
                    |b, &workers| {
                        b.iter_batched(
                            || setup_engine_with_workers(Some(workers)),
                            |harness| {
                                let EngineHarness {
                                    engine,
                                    tempdir,
                                    cfg,
                                } = harness;
                                let _keep_tempdir = tempdir;
                                let engine = Arc::clone(&engine);
                                let ops_per_thread = TOTAL_OPS / workers;

                                thread::scope(|scope| {
                                    for thread_idx in 0..workers {
                                        let engine = Arc::clone(&engine);
                                        scope.spawn(move || {
                                            let mut rng =
                                                StdRng::seed_from_u64(10_000 + thread_idx as u64);
                                            for _ in 0..ops_per_thread {
                                                let key = random_key(&mut rng, 32);
                                                let value = random_value(&mut rng, 256);
                                                engine.put(key, value).unwrap();
                                            }
                                        });
                                    }
                                });

                                drop(engine);
                                drop(cfg);
                            },
                            BatchSize::SmallInput,
                        );
                    },
                );
            }
        }
    }
    group.finish();
}

fn prepare_dataset(
    count: usize,
    key_len: usize,
    value_len: usize,
    rebuild: bool,
) -> (EngineHarness, Vec<Vec<u8>>) {
    let mut harness = setup_engine();
    let mut rng = StdRng::seed_from_u64(867);
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let key = random_key(&mut rng, key_len);
        let value = random_value(&mut rng, value_len);
        harness.engine.put(key.clone(), value).unwrap();
        keys.push(key);
    }
    if rebuild {
        harness.rebuild();
    }
    (harness, keys)
}

fn setup_engine() -> EngineHarness {
    setup_engine_with_workers(None)
}

fn setup_engine_with_workers(worker_threads: Option<usize>) -> EngineHarness {
    let tempdir = TempDir::new().unwrap();
    let mut cfg = StoreConfig::default();
    cfg.data_dir = tempdir.path().join("bench").to_string_lossy().into_owned();
    cfg.max_segment_size = 8 * 1024 * 1024;
    cfg.compaction_interval = std::time::Duration::from_secs(0);
    if let Some(workers) = worker_threads {
        cfg.worker_threads = workers;
    }
    let engine = Arc::new(SingleNodeEngine::with_config(cfg.clone()).unwrap());
    EngineHarness {
        engine,
        tempdir,
        cfg,
    }
}

fn random_key(rng: &mut StdRng, len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    rng.fill_bytes(&mut key);
    key
}

fn random_value(rng: &mut StdRng, len: usize) -> Vec<u8> {
    let mut value = vec![0u8; len];
    rng.fill_bytes(&mut value);
    value
}

struct EngineHarness {
    engine: Arc<SingleNodeEngine>,
    tempdir: TempDir,
    cfg: StoreConfig,
}

impl EngineHarness {
    fn rebuild(&mut self) {
        self.engine = Arc::new(SingleNodeEngine::with_config(self.cfg.clone()).unwrap());
    }
}

fn bench_prefix_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("prefix_queries");

    // Benchmark with different result set sizes
    for result_count in [10, 100, 1000] {
        group.bench_function(BenchmarkId::new("get_prefix", result_count), |b| {
            b.iter_batched(
                || prepare_prefix_dataset(10_000, result_count),
                |(harness, prefix)| {
                    let _ = harness.engine.get_prefix(&prefix).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }

    // Benchmark with different prefix lengths
    for prefix_len in [2, 8, 16] {
        group.bench_function(BenchmarkId::new("prefix_length", prefix_len), |b| {
            b.iter_batched(
                || prepare_prefix_length_dataset(10_000, prefix_len),
                |(harness, prefix)| {
                    let _ = harness.engine.get_prefix(&prefix).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_prefix_vs_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("prefix_vs_scan");

    group.bench_function("prefix_query_1000_of_10k", |b| {
        b.iter_batched(
            || prepare_prefix_dataset(10_000, 1000),
            |(harness, prefix)| {
                let _ = harness.engine.get_prefix(&prefix).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("manual_scan_1000_of_10k", |b| {
        b.iter_batched(
            || prepare_prefix_dataset(10_000, 1000),
            |(harness, prefix)| {
                let snapshot = harness.engine.read_with(|state| {
                    state.iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .map(|(k, (v, _version))| (k.clone(), v.clone()))
                        .collect::<Vec<_>>()
                });
                let _ = snapshot;
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_write_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_overhead");

    group.bench_function("put_1k_with_prefix_index", |b| {
        b.iter_batched(
            setup_engine,
            |harness| {
                let mut rng = StdRng::seed_from_u64(42);
                for _ in 0..1024 {
                    harness
                        .engine
                        .put(random_key(&mut rng, 16), random_value(&mut rng, 256))
                        .unwrap();
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn prepare_prefix_dataset(total_keys: usize, matching_keys: usize) -> (EngineHarness, Vec<u8>) {
    let harness = setup_engine();
    let mut rng = StdRng::seed_from_u64(1234);

    // Insert keys with matching prefix
    let prefix = b"app:user:".to_vec();
    for i in 0..matching_keys {
        let key = format!("app:user:{:08}", i).into_bytes();
        let value = random_value(&mut rng, 128);
        harness.engine.put(key, value).unwrap();
    }

    // Insert keys without matching prefix
    for _ in 0..(total_keys - matching_keys) {
        let key = random_key(&mut rng, 24);
        let value = random_value(&mut rng, 128);
        harness.engine.put(key, value).unwrap();
    }

    (harness, prefix)
}

fn prepare_prefix_length_dataset(total_keys: usize, prefix_len: usize) -> (EngineHarness, Vec<u8>) {
    let harness = setup_engine();
    let mut rng = StdRng::seed_from_u64(5678);

    // Create a fixed prefix of the desired length
    let prefix = vec![b'p'; prefix_len];

    // Insert 100 keys with matching prefix
    for i in 0..100 {
        let mut key = prefix.clone();
        key.extend_from_slice(format!(":{:08}", i).as_bytes());
        let value = random_value(&mut rng, 128);
        harness.engine.put(key, value).unwrap();
    }

    // Insert random keys without matching prefix
    for _ in 0..(total_keys - 100) {
        let key = random_key(&mut rng, 24);
        let value = random_value(&mut rng, 128);
        harness.engine.put(key, value).unwrap();
    }

    (harness, prefix)
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(40)
        .measurement_time(std::time::Duration::from_secs(20));
    targets = bench_engine_writes, bench_engine_reads, bench_compaction, bench_engine_writes_parallel,
              bench_prefix_queries, bench_prefix_vs_scan, bench_write_overhead
);
criterion_main!(benches);
