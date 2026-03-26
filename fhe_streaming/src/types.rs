// use tfhe::prelude::*;
use tfhe::{FheUint32, FheUint16, FheUint8};

#[derive(Clone)]
pub struct WorkerBucket {
    pub id: FheUint32,
    pub count: FheUint8, // 8-bit for fast stream processing
}

#[derive(Clone)]
pub struct WorkerState {
    pub buckets: Vec<WorkerBucket>,
    pub min_val: FheUint8,
    pub constants: (FheUint8, FheUint8),
}

#[derive(Clone)]
pub struct ParentBucket {
    pub id: FheUint32,
    pub count: FheUint16, // 16-bit to accumulate large frequencies
}

#[derive(Clone)]
pub struct ParentState {
    pub buckets: Vec<ParentBucket>,
}