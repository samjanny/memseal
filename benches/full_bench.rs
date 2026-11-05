use criterion::{Criterion, criterion_group, criterion_main};
use memseal::Vault;

fn bench_vault_create(c: &mut Criterion) {
    c.bench_function("Vault::create", |b| {
        b.iter(|| Vault::create(b"benchmark-password").unwrap());
    });
}

fn bench_vault_store(c: &mut Criterion) {
    let mut vault = Vault::create(b"benchmark-password").unwrap();
    c.bench_function("Vault::store", |b| {
        // Cycle through fewer names than MAX_INDEX_ENTRIES (1024): criterion
        // runs far more iterations than that, and a fresh name on every call
        // would hit the entry cap and fail. After the first pass the calls
        // overwrite existing entries, which is still the store() path.
        let mut i = 0u64;
        b.iter(|| {
            let name = format!("key_{}", i % 1000);
            vault.store(&name, b"benchmark-value-data").unwrap();
            i += 1;
        });
    });
}

fn bench_vault_retrieve(c: &mut Criterion) {
    let mut vault = Vault::create(b"benchmark-password").unwrap();
    vault.store("target_key", b"target-value-data").unwrap();
    c.bench_function("Vault::retrieve", |b| {
        b.iter(|| vault.retrieve("target_key").unwrap());
    });
}

fn bench_vault_with_secret(c: &mut Criterion) {
    let mut vault = Vault::create(b"benchmark-password").unwrap();
    vault.store("target_key", b"target-value-data").unwrap();
    c.bench_function("Vault::with_secret", |b| {
        b.iter(|| {
            vault
                .with_secret("target_key", |secret| std::hint::black_box(secret).len())
                .unwrap()
        });
    });
}

fn bench_vault_export(c: &mut Criterion) {
    let mut vault = Vault::create(b"benchmark-password").unwrap();
    vault.store("key1", b"value1").unwrap();
    vault.store("key2", b"value2").unwrap();
    vault.store("key3", b"value3").unwrap();
    c.bench_function("Vault::export (3 entries)", |b| {
        b.iter(|| vault.export().unwrap());
    });
}

fn bench_vault_roundtrip(c: &mut Criterion) {
    c.bench_function("Vault create+store+export+open+retrieve", |b| {
        b.iter(|| {
            let mut vault = Vault::create(b"benchmark-password").unwrap();
            vault.store("secret", b"secret-value").unwrap();
            let bytes = vault.export().unwrap();
            let reopened = Vault::open(b"benchmark-password", &bytes).unwrap();
            reopened.retrieve("secret").unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_vault_create,
    bench_vault_store,
    bench_vault_retrieve,
    bench_vault_with_secret,
    bench_vault_export,
    bench_vault_roundtrip,
);
criterion_main!(benches);
