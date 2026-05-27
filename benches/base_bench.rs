use criterion::{Criterion, criterion_group, criterion_main};

fn trivial_bench(c: &mut Criterion) {
    c.bench_function("Trivial_Bench", |b| b.iter(|| 1 + 2));
}

criterion_group!(benches, trivial_bench);
criterion_main!(benches);
