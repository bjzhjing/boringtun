use aead::{AeadInPlace, NewAead};
use criterion::{BenchmarkId, Criterion, Throughput};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

fn chacha20poly1305_ring(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap());

    let x = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(&[]),
            &mut buf[..n],
        )
        .map(|tag| {
            buf[n..].copy_from_slice(tag.as_ref());
            len
        })
        .unwrap();

    criterion::black_box(x);
}

fn chacha20poly1305(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key_bytes).unwrap();
    let nonce = chacha20poly1305::Nonce::default();

    let x = aead
        .encrypt_in_place_detached(&nonce, &[], &mut buf[..n])
        .map(|tag| {
            buf[n..].copy_from_slice(tag.as_ref());
            n
        })
        .unwrap();

    criterion::black_box(x);
}

fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305");

    for size in [128, 192, 1400, 8192] {
        group.throughput(Throughput::Bytes(128 as u64));

        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_ring", size),
            &size,
            |b, i| {
                let key = [0; 32];
                let mut buf = vec![0; i + 16];

                b.iter(|| chacha20poly1305_ring(&key, &mut buf));
            },
        );

        group.bench_with_input(BenchmarkId::new("chacha20poly1305", size), &size, |b, i| {
            let key = [0; 32];
            let mut buf = vec![0; i + 16];

            b.iter(|| chacha20poly1305(&key, &mut buf));
        });
    }
}

criterion::criterion_group!(chacha20poly1305_benches, bench_chacha20poly1305);
criterion::criterion_main!(chacha20poly1305_benches);