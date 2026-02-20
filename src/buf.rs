use bytes::BytesMut;
use std::sync::Mutex;

/// A simple pool of `BytesMut` buffers bucketed by size class (powers of 2).
/// Sizes: 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB.
const SIZE_CLASSES: &[usize] = &[1024, 2048, 4096, 8192, 16384, 32768, 65536];
const MAX_POOL_PER_CLASS: usize = 64;

static POOL: std::sync::OnceLock<BufPool> = std::sync::OnceLock::new();

struct BufPool {
    buckets: Vec<Mutex<Vec<BytesMut>>>,
}

impl BufPool {
    fn new() -> Self {
        Self {
            buckets: SIZE_CLASSES
                .iter()
                .map(|_| Mutex::new(Vec::new()))
                .collect(),
        }
    }

    fn class_for(size: usize) -> Option<usize> {
        SIZE_CLASSES.iter().position(|&s| s >= size)
    }

    fn get(&self, min_size: usize) -> BytesMut {
        if let Some(idx) = Self::class_for(min_size) {
            let mut bucket = self.buckets[idx].lock().unwrap();
            if let Some(mut buf) = bucket.pop() {
                buf.clear();
                return buf;
            }
            return BytesMut::with_capacity(SIZE_CLASSES[idx]);
        }
        BytesMut::with_capacity(min_size)
    }

    fn put(&self, buf: BytesMut) {
        let cap = buf.capacity();
        if let Some(idx) = Self::class_for(cap) {
            let mut bucket = self.buckets[idx].lock().unwrap();
            if bucket.len() < MAX_POOL_PER_CLASS {
                bucket.push(buf);
            }
        }
    }
}

fn pool() -> &'static BufPool {
    POOL.get_or_init(BufPool::new)
}

/// Acquire a `BytesMut` with at least `min_size` capacity from the pool.
pub fn get(min_size: usize) -> BytesMut {
    pool().get(min_size)
}

/// Return a `BytesMut` to the pool.
pub fn put(buf: BytesMut) {
    pool().put(buf);
}
