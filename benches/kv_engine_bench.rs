use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use hightower_kv::{KvEngine, SingleNodeEngine, StoreConfig};
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

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(40)
        .measurement_time(std::time::Duration::from_secs(20));
    targets = bench_engine_writes, bench_engine_reads, bench_compaction, bench_engine_writes_parallel
);
criterion_main!(benches);
