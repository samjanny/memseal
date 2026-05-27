use criterion::{Criterion, criterion_group, criterion_main};
use memseal::mem::secure_memory_vault::SecureMemoryVault;

fn benchmark_vault_write(c: &mut Criterion) {
    let data = vec![42u8; 10_000_000];
    c.bench_function("SecureMemoryVault::new", |b| {
        b.iter(|| {
            let _ = SecureMemoryVault::new(&data).expect("Vault creation failed");
        });
    });
}

fn benchmark_vec_write(c: &mut Criterion) {
    let data = vec![42u8; 10_000_000];
    c.bench_function("Vec<u8>::clone", |b| {
        b.iter(|| {
            let _ = data.clone();
        });
    });
}

fn benchmark_vault_read(c: &mut Criterion) {
    let data = vec![42u8; 10_000_000];
    let vault = SecureMemoryVault::new(&data).expect("Vault creation failed");

    c.bench_function("SecureMemoryVault::access", |b| {
        b.iter(|| {
            let mut result = Vec::new();
            vault
                .access(|chunk, _| {
                    result.extend_from_slice(chunk);
                    Ok(())
                })
                .expect("Vault access failed");
        });
    });
}

fn benchmark_vec_read(c: &mut Criterion) {
    let data = vec![42u8; 10_000_000];
    c.bench_function("Vec<u8>::read", |b| {
        b.iter(|| {
            let mut result = Vec::new();
            result.extend_from_slice(&data);
        });
    });
}

criterion_group!(
    benches,
    benchmark_vault_write,
    benchmark_vec_write,
    benchmark_vault_read,
    benchmark_vec_read
);
criterion_main!(benches);
