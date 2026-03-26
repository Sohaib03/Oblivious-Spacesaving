use crate::types::{WorkerState, ParentState, ParentBucket};
use crate::config::AppConfig;
use tfhe::prelude::*;
use tfhe::{FheUint32, FheUint16, FheUint8, FheBool, set_server_key, ServerKey};
use rayon::prelude::*;
use crossbeam_channel::Receiver;
use log::info;

pub fn spawn_aggregator(
    config: AppConfig,
    server_key: ServerKey,
    flush_rx: Receiver<WorkerState>,
) -> ParentState {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.system.aggregator_threads)
        .start_handler({
            let sk = server_key.clone();
            move |_| set_server_key(sk.clone())
        })
        .build()
        .unwrap();

    pool.install(move || {
        set_server_key(server_key.clone());
        let k = config.algorithm.table_size_k;

        let mut parent_state = ParentState {
            buckets: vec![ParentBucket {
                id: FheUint32::encrypt_trivial(0u32),
                count: FheUint16::encrypt_trivial(0u16),
            }; k],
        };

        let mut merges_completed = 0;

        // Block and wait for flushed states from workers
        for worker_state in flush_rx {
            info!("Aggregator received a state. Initiating 8-bit to 16-bit merge...");

            // 1. Cast the 8-bit incoming state to 16-bit format in parallel
            // let casted_buckets: Vec<(FheUint32, FheUint16)> = worker_state.buckets.par_iter()
            //     .map(|b| {
            //         let count_16bit: FheUint16 = b.count.cast_into();
            //         (b.id.clone(), count_16bit)
            //     })
            //     .collect();

            let casted_buckets: Vec<(FheUint32, FheUint16)> = worker_state.buckets.into_par_iter()
                .map(|b| {
                    let count_16bit: FheUint16 = b.count.cast_into();
                    (b.id, count_16bit) // We can also drop the .clone() on b.id now!
                })
                .collect();

            // 2. Process each bucket from the worker state
            for (item, freq) in casted_buckets {
                let hits: Vec<FheBool> = parent_state.buckets.par_iter().map(|b| b.id.eq(&item)).collect();
                let found = hits.par_iter().cloned().reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);

                // Find global minimum in 16-bit parent state
                let indexed_counts: Vec<(FheUint16, FheUint8)> = parent_state.buckets.par_iter().enumerate()
                    .map(|(i, b)| (b.count.clone(), FheUint8::encrypt_trivial(i as u8))).collect();

                let (min_val, victim_idx) = indexed_counts.par_iter().cloned()
                    .reduce(
                        || (FheUint16::encrypt_trivial(u16::MAX), FheUint8::encrypt_trivial(255u8)),
                        | (val_a, idx_a), (val_b, idx_b) | {
                            let pick_a = val_a.le(&val_b); 
                            (pick_a.select(&val_a, &val_b), pick_a.select(&idx_a, &idx_b))
                        }
                    );

                let victim_mask: Vec<FheBool> = (0..k).into_par_iter()
                    .map(|i| victim_idx.eq(i as u8)).collect();

                // Unified conditional update
                let val_if_victim_global = &min_val + &freq;
                let zero_freq = FheUint16::encrypt_trivial(0u16);
                let is_non_zero_freq = freq.ne(&zero_freq); // CRITICAL: Prevent empty bucket overwrites
                let valid_miss = !&found & is_non_zero_freq;

                parent_state.buckets.par_iter_mut().zip(hits.par_iter()).zip(victim_mask.par_iter())
                    .for_each(|((bucket, is_hit), is_victim_ptr)| {
                        let is_victim_miss = is_victim_ptr & &valid_miss;
                        let val_if_hit = &bucket.count + &freq;
                        
                        let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);
                        bucket.count = is_victim_miss.select(&val_if_victim_global, &after_hit_check);
                        bucket.id = is_victim_miss.select(&item, &bucket.id);
                    });
            }
            merges_completed += 1;
            info!("Merge {} complete.", merges_completed);
        }

        info!("All workers disconnected. Aggregator returning final state.");
        parent_state
    })
}