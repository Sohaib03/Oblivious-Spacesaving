use crate::types::{WorkerState, WorkerBucket};
use crate::config::AppConfig;
use tfhe::prelude::*;
use tfhe::{FheUint32, FheUint8, FheBool, set_server_key, ServerKey};
use rayon::prelude::*;
use crossbeam_channel::{Receiver, Sender};
use log::info;
use indicatif::ProgressBar; // <-- New import

pub fn spawn_worker(
    worker_id: usize,
    config: AppConfig,
    server_key: ServerKey,
    item_rx: Receiver<FheUint32>,
    flush_tx: Sender<WorkerState>,
    pb: ProgressBar, // <-- New parameter
) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.system.worker_threads)
        .start_handler({
            let sk = server_key.clone();
            move |_| set_server_key(sk.clone())
        })
        .build()
        .unwrap();

    pool.install(move || {
        set_server_key(server_key.clone());
        let k = config.algorithm.table_size_k;
        
        let mut state = WorkerState {
            buckets: vec![WorkerBucket {
                id: FheUint32::encrypt_trivial(0u32),
                count: FheUint8::encrypt_trivial(0u8),
            }; k],
            min_val: FheUint8::encrypt_trivial(0u8),
            constants: (FheUint8::encrypt_trivial(0u8), FheUint8::encrypt_trivial(1u8)),
        };

        let mut local_updates = 0;

        for item in item_rx {
            // FHE Hit Detection
            let is_match: Vec<FheBool> = state.buckets.par_iter().map(|b| b.id.eq(&item)).collect();
            let found_any = is_match.par_iter().cloned().reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);

            // Victim Selection
            let is_min: Vec<FheBool> = state.buckets.par_iter().map(|b| b.count.eq(&state.min_val)).collect();
            let (victim_mask, _) = parallel_first_one(&is_min);

            // Update
            state.buckets.par_iter_mut().enumerate().for_each(|(i, bucket)| {
                let miss_logic = &victim_mask[i] & !&found_any;
                let do_increment = &is_match[i] | &miss_logic;
                let increment = do_increment.select(&state.constants.1, &state.constants.0);
                
                bucket.count = &bucket.count + &increment;
                bucket.id = miss_logic.select(&item, &bucket.id);
            });

            // Floor Maintenance
            let any_at_floor = state.buckets.par_iter()
                .map(|b| b.count.eq(&state.min_val))
                .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
            let increment = (!any_at_floor).select(&state.constants.1, &state.constants.0);
            state.min_val = &state.min_val + increment;

            local_updates += 1;
            pb.inc(1); // <-- Increment the shared progress bar!

            // FLUSH LOGIC
            if local_updates >= config.algorithm.flush_threshold {
                info!("Worker {} hit threshold. Flushing...", worker_id);
                flush_tx.send(state.clone()).unwrap();
                
                state.buckets.par_iter_mut().for_each(|b| {
                    b.id = FheUint32::encrypt_trivial(0u32);
                    b.count = FheUint8::encrypt_trivial(0u8);
                });
                state.min_val = FheUint8::encrypt_trivial(0u8);
                local_updates = 0;
            }
        }

        if local_updates > 0 {
            flush_tx.send(state).unwrap();
        }
    });
}

// ... parallel_first_one helper function remains exactly the same ...
fn parallel_first_one(cands: &[FheBool]) -> (Vec<FheBool>, FheBool) {
    let len = cands.len();
    if len == 0 { return (Vec::new(), FheBool::encrypt_trivial(false)); }
    if len == 1 { return (vec![cands[0].clone()], cands[0].clone()); }
    let mid = len / 2;
    let ((mut left_mask, left_any), (right_mask, right_any)) = rayon::join(
        || parallel_first_one(&cands[..mid]), || parallel_first_one(&cands[mid..])
    );
    let not_left_any = !&left_any;
    let masked_right: Vec<FheBool> = right_mask.par_iter().map(|r| r & &not_left_any).collect();
    left_mask.extend(masked_right);
    (left_mask, left_any | &right_any)
}