use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::hint::black_box;
use tobira::relay::transport::grpc::{decode_grpc_frame_data, encode_grpc_frame};

const TOTAL_BYTES: usize = 4 * 1024 * 1024;

fn make_frames(frame_size: usize) -> Vec<Bytes> {
    let frame_count = TOTAL_BYTES / frame_size;
    let payload = vec![0xAB; frame_size];
    (0..frame_count)
        .map(|_| encode_grpc_frame(&payload))
        .collect()
}

fn read_initial_auth_from_frames(frames: &[Bytes]) -> (usize, [u8; 16]) {
    let mut cached_frame_count = 0usize;
    let mut initial_raw = Vec::new();

    for frame in frames {
        let data = decode_grpc_frame_data(frame).expect("benchmark frame must decode");
        initial_raw.extend_from_slice(data);
        cached_frame_count += 1;

        if initial_raw.len() >= 16 {
            break;
        }
    }

    let auth_id = initial_raw[..16].try_into().unwrap();
    (cached_frame_count, auth_id)
}

fn fast_path_auth_scan_and_forward(frames: &[Bytes]) -> usize {
    let (cached_frame_count, auth_id) = read_initial_auth_from_frames(frames);
    let mut forwarded = Vec::with_capacity(frames.len());
    let mut total = 0usize;

    black_box(auth_id);

    for frame in &frames[..cached_frame_count] {
        total += frame.len();
        forwarded.push(frame.clone());
    }
    for frame in &frames[cached_frame_count..] {
        total += frame.len();
        forwarded.push(frame.clone());
    }

    black_box(forwarded);
    total
}

fn core_decode_reencode(frames: &[Bytes]) -> usize {
    let mut forwarded = Vec::with_capacity(frames.len());
    let mut total = 0usize;

    for frame in frames {
        let payload = decode_grpc_frame_data(frame).expect("benchmark frame must decode");
        let encoded = encode_grpc_frame(payload);
        total += encoded.len();
        forwarded.push(encoded);
    }

    black_box(forwarded);
    total
}

fn bench_grpc_bridge(c: &mut Criterion) {
    for frame_size in [4 * 1024, 16 * 1024] {
        let frames = make_frames(frame_size);
        let mut group = c.benchmark_group(format!("grpc_bridge_{}k_frames", frame_size / 1024));
        group.throughput(Throughput::Bytes(TOTAL_BYTES as u64));

        group.bench_function("fast_path_auth_scan_and_forward", |b| {
            b.iter_batched_ref(
                || frames.clone(),
                |frames| black_box(fast_path_auth_scan_and_forward(frames)),
                BatchSize::SmallInput,
            );
        });

        group.bench_function("core_decode_reencode", |b| {
            b.iter_batched_ref(
                || frames.clone(),
                |frames| black_box(core_decode_reencode(frames)),
                BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

criterion_group!(benches, bench_grpc_bridge);
criterion_main!(benches);
