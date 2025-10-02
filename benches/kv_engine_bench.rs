use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use hightower_kv::{KvEngine, SingleNodeEngine, StoreConfig};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tempfile::TempDir;

fn bench_engine_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_writes");
    for (label, key_len, value_len) in [
        ("small", 16, 64),
        ("medium", 16, 512),
        ("large", 32, 4096),
    ] {
        group.bench_with_input(BenchmarkId::new("put_1k", label), &(key_len, value_len), |b, &(k, v)| {
            b.iter_batched(
                setup_engine,
                |mut harness| {
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
        });
    }
    group.finish();
}

fn bench_engine_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_reads");
    for (label, cold) in [("hot", false), ("cold", true)] {
        group.bench_function(BenchmarkId::new("get_4k", label), |b| {
            b.iter_batched(
                || prepare_dataset(4096, 16, 256, cold),
                |(mut harness, keys)| {
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
                let mut harness = setup_engine();
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
            |mut harness| {
                harness.engine.run_compaction_now().unwrap();
            },
            BatchSize::SmallInput,
        );
    });
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
    let tempdir = TempDir::new().unwrap();
    let mut cfg = StoreConfig::default();
    cfg.data_dir = tempdir
        .path()
        .join("bench")
        .to_string_lossy()
        .into_owned();
    cfg.max_segment_size = 8 * 1024 * 1024;
    cfg.compaction_interval = std::time::Duration::from_secs(0);
    let engine = SingleNodeEngine::with_config(cfg.clone()).unwrap();
    EngineHarness {
        engine,
        _tempdir: tempdir,
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
    engine: SingleNodeEngine,
    _tempdir: TempDir,
    cfg: StoreConfig,
}

impl EngineHarness {
    fn rebuild(&mut self) {
        self.engine = SingleNodeEngine::with_config(self.cfg.clone()).unwrap();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(40)
        .measurement_time(std::time::Duration::from_secs(20));
    targets = bench_engine_writes, bench_engine_reads, bench_compaction
);
criterion_main!(benches);
