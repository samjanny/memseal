use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use memseal::crypto::aad_aead::{open_with_aad, seal_with_aad};
use memseal::crypto::nonce_rotation::{NonceRotation, derive_nonce_from_counter};
use memseal::crypto::utils::secure_bytes_fill;
use memseal::mem::secure_memory_vault::SecureMemoryVault;
use memseal::vault::vault_header::VaultHeader;
use memseal::vault::vault_index::{IndexMetaBlockLocation, IndexMetaBlockMetadata, VaultIndex};

fn bench_vault_new_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("SecureMemoryVault::new");
    for size in [32, 1024, 4096, 64_000, 1_000_000] {
        let data = vec![42u8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| SecureMemoryVault::new(data).unwrap());
        });
    }
    group.finish();
}

fn bench_vault_access_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("SecureMemoryVault::access");
    for size in [32, 1024, 4096, 64_000, 1_000_000] {
        let data = vec![42u8; size];
        let vault = SecureMemoryVault::new(&data).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &vault, |b, vault| {
            b.iter(|| {
                let mut out = Vec::new();
                vault
                    .access(|chunk, _| {
                        out.extend_from_slice(chunk);
                        Ok(())
                    })
                    .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_vault_index_generate(c: &mut Criterion) {
    c.bench_function("VaultIndex::generate", |b| {
        b.iter(|| VaultIndex::generate().unwrap());
    });
}

fn bench_nonce_rotation(c: &mut Criterion) {
    c.bench_function("VaultIndex::rotate_nonce", |b| {
        b.iter_batched(
            || VaultIndex::generate().unwrap(),
            |idx| idx.rotate_nonce().unwrap(),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_derive_nonce(c: &mut Criterion) {
    let key = [0x42u8; 32];
    c.bench_function("derive_nonce_from_counter", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            derive_nonce_from_counter(&key, counter, &[]).unwrap()
        });
    });
}

fn bench_hmac_lookup(c: &mut Criterion) {
    let mut idx = VaultIndex::generate().unwrap();
    for i in 0..100 {
        let meta = IndexMetaBlockMetadata::new(
            IndexMetaBlockLocation::LargeFile {
                metablock_uid: format!("uid{}", i),
            },
            1000,
            2000,
            false,
            None,
            None,
            0,
        );
        idx.insert_file(&format!("file_{}.txt", i), meta).unwrap();
    }

    c.bench_function("VaultIndex::lookup_file (100 entries)", |b| {
        b.iter(|| idx.lookup_file("file_50.txt").unwrap());
    });
}

fn bench_hmac_insert(c: &mut Criterion) {
    c.bench_function("VaultIndex::insert_file", |b| {
        b.iter_batched(
            || VaultIndex::generate().unwrap(),
            |mut idx| {
                let meta = IndexMetaBlockMetadata::new(
                    IndexMetaBlockLocation::LargeFile {
                        metablock_uid: "uid".to_string(),
                    },
                    1000,
                    2000,
                    false,
                    None,
                    None,
                    0,
                );
                idx.insert_file("test_file.txt", meta).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_header_aad(c: &mut Criterion) {
    let header = VaultHeader::generate().unwrap();
    c.bench_function("VaultHeader::to_aad_bytes", |b| {
        b.iter(|| header.to_aad_bytes().unwrap());
    });
}

fn bench_seal_with_aad(c: &mut Criterion) {
    let mut group = c.benchmark_group("seal_with_aad");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    secure_bytes_fill(&mut key).unwrap();
    secure_bytes_fill(&mut nonce).unwrap();
    let aad = b"header aad bytes for authentication";

    for size in [64, 1024, 64_000, 1_000_000] {
        let plaintext = vec![0x42u8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| seal_with_aad(&key, &nonce, pt, aad).unwrap());
        });
    }
    group.finish();
}

fn bench_open_with_aad(c: &mut Criterion) {
    let mut group = c.benchmark_group("open_with_aad");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    secure_bytes_fill(&mut key).unwrap();
    secure_bytes_fill(&mut nonce).unwrap();
    let aad = b"header aad bytes for authentication";

    for size in [64, 1024, 64_000, 1_000_000] {
        let plaintext = vec![0x42u8; size];
        let ct = seal_with_aad(&key, &nonce, &plaintext, aad).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &ct, |b, ct| {
            b.iter(|| open_with_aad(&key, &nonce, ct, aad).unwrap());
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_vault_new_sizes,
    bench_vault_access_sizes,
    bench_vault_index_generate,
    bench_nonce_rotation,
    bench_derive_nonce,
    bench_hmac_lookup,
    bench_hmac_insert,
    bench_header_aad,
    bench_seal_with_aad,
    bench_open_with_aad,
);
criterion_main!(benches);
