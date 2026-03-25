use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32, FheUint8, FheUint16};
use rayon::prelude::*;
use rand::prelude::*;
use rand_distr::Zipf;
use rand_distr::Distribution;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct EncryptedBucket {
    id: FheUint32,
    count: FheUint32,
}

struct EncryptedState {
    buckets: Vec<EncryptedBucket>,
}

#[derive(Debug, Default, Clone, Copy)]
struct UpdateMetrics {
    phase1_hit: Duration,
    phase2_min: Duration,
    phase3_victim: Duration,
    phase4_update: Duration,
}

impl UpdateMetrics {
    fn add(&mut self, other: &UpdateMetrics) {
        self.phase1_hit += other.phase1_hit;
        self.phase2_min += other.phase2_min;
        self.phase3_victim += other.phase3_victim;
        self.phase4_update += other.phase4_update;
    }
}

// Plaintext SpaceSaving for a single stream insert (for validation)
fn insert_plaintext(buckets: &mut [(u32, u32)], item: u32) {
    let mut hit_idx = None;
    for (i, (id, _)) in buckets.iter().enumerate() {
        if *id == item && *id != 0 { 
            hit_idx = Some(i);
            break;
        }
    }

    match hit_idx {
        Some(i) => buckets[i].1 += 1,
        None => {
            let min_val = buckets.iter().map(|(_, cnt)| *cnt).min().unwrap_or(0);
            if let Some((i, _)) = buckets.iter().enumerate().find(|(_, (_, cnt))| *cnt == min_val) {
                buckets[i].0 = item;
                buckets[i].1 = min_val + 1;
            }
        }
    }
}

// Generates a Zipfian distribution of stream items
fn generate_zipf_stream(len: usize, max_val: u32, exponent: f64) -> Vec<u32> {
    let mut rng = thread_rng();
    let zipf = Zipf::new(max_val as u64, exponent).expect("valid zipf params");
    (0..len).map(|_| zipf.sample(&mut rng) as u32 + 1).collect()
}
// fn generate_zipf_stream(len: usize, max_val: u32, exponent: f64) -> Vec<u32> {
//     let mut rng = thread_rng();
//     // FIX: Cast max_val to f64 so it matches the f64 exponent
//     let zipf = Zipf::new(max_val as f64, exponent).expect("valid zipf params");
    
//     // zipf.sample returns an f64, which we cast back down to u32
//     (0..len).map(|_| zipf.sample(&mut rng) as u32 + 1).collect()
// }

// Oblivious stream update
// fn update_item_oblivious(
//     state: &mut EncryptedState,
//     item: &FheUint32,
// ) -> UpdateMetrics {
//     let mut metrics = UpdateMetrics::default();

//     // --- PHASE 1: HIT DETECTION ---
//     let t0 = Instant::now();
//     let hits: Vec<FheBool> = state.buckets.par_chunks(4)
//         .flat_map(|chunk| {
//             chunk.iter().map(|b| b.id.eq(item)).collect::<Vec<_>>()
//         })
//         .collect();
    
//     let found = hits.par_iter().cloned()
//         .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
//     metrics.phase1_hit = t0.elapsed();

//     // --- PHASE 2: AUGMENTED MIN REDUCTION ---
//     let t1 = Instant::now();
//     let indexed_counts: Vec<(FheUint32, FheUint8)> = state.buckets.par_iter().enumerate()
//         .map(|(i, b)| {
//             (b.count.clone(), FheUint8::encrypt_trivial(i as u8))
//         })
//         .collect();

//     let (min_val, victim_idx) = indexed_counts.par_chunks(4)
//         .map(|chunk| {
//             let mut local_best = chunk[0].clone();
//             for next in &chunk[1..] {
//                 let (best_val, best_idx) = &local_best;
//                 let (curr_val, curr_idx) = next;
                
//                 let pick_new = curr_val.lt(best_val); 
//                 local_best = (
//                     pick_new.select(curr_val, best_val),
//                     pick_new.select(curr_idx, best_idx)
//                 );
//             }
//             local_best
//         })
//         .reduce(
//             || (FheUint32::encrypt_trivial(u32::MAX), FheUint8::encrypt_trivial(255u8)),
//             | (val_a, idx_a), (val_b, idx_b) | {
//                 let pick_a = val_a.le(&val_b); 
//                 (
//                     pick_a.select(&val_a, &val_b), 
//                     pick_a.select(&idx_a, &idx_b) 
//                 )
//             }
//         );
//     metrics.phase2_min = t1.elapsed();

//     // --- PHASE 3: CHEAP MASK GENERATION ---
//     let t2 = Instant::now();
//     let victim_mask: Vec<FheBool> = (0..state.buckets.len()).into_par_iter()
//         .map(|i| {
//             victim_idx.eq(i as u8) 
//         })
//         .collect();
//     metrics.phase3_victim = t2.elapsed();

//     // --- PHASE 4: UNIFIED UPDATE ---
//     let t3 = Instant::now();

//     let one = FheUint32::encrypt_trivial(1u32);
//     let val_if_victim_global = &min_val + &one;
//     let not_found = !&found;

//     state.buckets.par_chunks_mut(4)
//         .zip(hits.par_chunks(4))
//         .zip(victim_mask.par_chunks(4))
//         .for_each(|((bucket_chunk, hit_chunk), mask_chunk)| {
//             for i in 0..bucket_chunk.len() {
//                 let bucket = &mut bucket_chunk[i];
//                 let is_hit = &hit_chunk[i];
//                 let is_victim_ptr = &mask_chunk[i];

//                 let is_victim_miss = is_victim_ptr & &not_found;

//                 let val_if_hit = &bucket.count + &one;
//                 let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);
//                 bucket.count = is_victim_miss.select(&val_if_victim_global, &after_hit_check);

//                 bucket.id = is_victim_miss.select(item, &bucket.id);
//             }
//         });

//     metrics.phase4_update = t3.elapsed();
//     metrics
// }

// Oblivious stream update (Optimized for High Core Count)
// fn update_item_oblivious(
//     state: &mut EncryptedState,
//     item: &FheUint32,
// ) -> UpdateMetrics {
//     let mut metrics = UpdateMetrics::default();

//     // --- PHASE 1: HIT DETECTION ---
//     let t0 = Instant::now();
    
//     // Directly parallelize over all items instead of chunking
//     let hits: Vec<FheBool> = state.buckets.par_iter()
//         .map(|b| b.id.eq(item))
//         .collect();
    
//     let found = hits.par_iter().cloned()
//         .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    
//     metrics.phase1_hit = t0.elapsed();

//     // --- PHASE 2: AUGMENTED MIN REDUCTION ---
//     let t1 = Instant::now();
//     let indexed_counts: Vec<(FheUint32, FheUint8)> = state.buckets.par_iter().enumerate()
//         .map(|(i, b)| {
//             (b.count.clone(), FheUint8::encrypt_trivial(i as u8))
//         })
//         .collect();

//     let (min_val, victim_idx) = indexed_counts.par_chunks(4)
//         .map(|chunk| {
//             let mut local_best = chunk[0].clone();
//             for next in &chunk[1..] {
//                 let (best_val, best_idx) = &local_best;
//                 let (curr_val, curr_idx) = next;
                
//                 let pick_new = curr_val.lt(best_val); 
//                 local_best = (
//                     pick_new.select(curr_val, best_val),
//                     pick_new.select(curr_idx, best_idx)
//                 );
//             }
//             local_best
//         })
//         .reduce(
//             || (FheUint32::encrypt_trivial(u32::MAX), FheUint8::encrypt_trivial(255u8)),
//             | (val_a, idx_a), (val_b, idx_b) | {
//                 let pick_a = val_a.le(&val_b); 
//                 (
//                     pick_a.select(&val_a, &val_b), 
//                     pick_a.select(&idx_a, &idx_b) 
//                 )
//             }
//         );
//     metrics.phase2_min = t1.elapsed();   

//     // --- PHASE 3: CHEAP MASK GENERATION ---
//     let t2 = Instant::now();
//     let victim_mask: Vec<FheBool> = (0..state.buckets.len()).into_par_iter()
//         .map(|i| {
//             victim_idx.eq(i as u8) 
//         })
//         .collect();
        
//     metrics.phase3_victim = t2.elapsed();

//     // --- PHASE 4: UNIFIED UPDATE ---
//     let t3 = Instant::now();

//     // Hoisted loop-invariant calculations
//     let one = FheUint32::encrypt_trivial(1u32);
//     let val_if_victim_global = &min_val + &one;
//     let not_found = !&found;

//     // Direct zipped parallel iteration over the exact bucket count
//     state.buckets.par_iter_mut()
//         .zip(hits.par_iter())
//         .zip(victim_mask.par_iter())
//         .for_each(|((bucket, is_hit), is_victim_ptr)| {
            
//             let is_victim_miss = is_victim_ptr & &not_found;

//             // A. Calculate Hit Value
//             let val_if_hit = &bucket.count + &one;
            
//             // B. MUX Logic
//             let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);
//             bucket.count = is_victim_miss.select(&val_if_victim_global, &after_hit_check);

//             // C. ID Update
//             bucket.id = is_victim_miss.select(item, &bucket.id);
//         });

//     metrics.phase4_update = t3.elapsed();
    
//     metrics
// }

// Oblivious stream update (Optimized State Update, Phase 2 Intact)
fn update_item_oblivious(
    state: &mut EncryptedState,
    item: &FheUint32,
) -> UpdateMetrics {
    let mut metrics = UpdateMetrics::default();

    // --- PHASE 1: HIT DETECTION ---
    let t0 = Instant::now();
    
    let hits: Vec<FheBool> = state.buckets.par_iter()
        .map(|b| b.id.eq(item))
        .collect();
    
    let found = hits.par_iter().cloned()
        .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    
    metrics.phase1_hit = t0.elapsed();

    // --- PHASE 2: AUGMENTED MIN REDUCTION (INTACT FOR BENCHMARKING) ---
    // let t1 = Instant::now();
    // let indexed_counts: Vec<(FheUint32, FheUint8)> = state.buckets.par_iter().enumerate()
    //     .map(|(i, b)| {
    //         (b.count.clone(), FheUint8::encrypt_trivial(i as u8))
    //     })
    //     .collect();

    // let (min_val, victim_idx) = indexed_counts.par_iter()
    //     .cloned() 
    //     .reduce(
    //         || (FheUint32::encrypt_trivial(u32::MAX), FheUint8::encrypt_trivial(255u8)),
    //         | (val_a, idx_a), (val_b, idx_b) | {
    //             let pick_a = val_a.le(&val_b); 
    //             (
    //                 pick_a.select(&val_a, &val_b), 
    //                 pick_a.select(&idx_a, &idx_b) 
    //             )
    //         }
    //     );
        
    // metrics.phase2_min = t1.elapsed();
    // --- PHASE 2: NAIVE SEQUENTIAL MIN SEARCH ---
    let t1 = Instant::now();
    
    // Initialize tracking variables with maximum possible value
    let mut min_val = FheUint32::encrypt_trivial(u32::MAX);
    let mut victim_idx = FheUint8::encrypt_trivial(255u8);

    // Sequentially iterate through every bucket on a single thread
    for (i, bucket) in state.buckets.iter().enumerate() {
        let curr_idx = FheUint8::encrypt_trivial(i as u8);
        
        // Compare current bucket's count with the running minimum
        let pick_new = bucket.count.lt(&min_val); 
        
        // Update running minimum and index using MUX (select)
        min_val = pick_new.select(&bucket.count, &min_val);
        victim_idx = pick_new.select(&curr_idx, &victim_idx);
    }
        
    metrics.phase2_min = t1.elapsed();

    // --- PHASE 3: CHEAP MASK GENERATION ---
    let t2 = Instant::now();
    let victim_mask: Vec<FheBool> = (0..state.buckets.len()).into_par_iter()
        .map(|i| {
            victim_idx.eq(i as u8) 
        })
        .collect();
        
    metrics.phase3_victim = t2.elapsed();

    // --- PHASE 4: UNIFIED UPDATE (OPTIMIZED ADDITIVE LOGIC) ---
    let t3 = Instant::now();

    // Hoisted constants for the update
    let zero = FheUint32::encrypt_trivial(0u32);
    let one = FheUint32::encrypt_trivial(1u32);
    let not_found = !&found;

    state.buckets.par_iter_mut()
        .zip(hits.par_iter())
        .zip(victim_mask.par_iter())
        .for_each(|((bucket, is_hit), is_victim_ptr)| {
            
            // miss_logic is true ONLY if this bucket is the chosen victim AND the item was not found
            let miss_logic = is_victim_ptr & &not_found;

            // Optimization: Combine flags. We increment if it's a hit, OR if it's a victim miss.
            let do_increment = is_hit | &miss_logic;
            let increment = do_increment.select(&one, &zero);

            // Update Count: Add 0 or 1.
            // (If it's a victim, its current count is already min_val, so adding 1 makes it min_val + 1)
            bucket.count = &bucket.count + &increment;

            // Update ID: Overwrite with new item ONLY if it's a victim miss
            bucket.id = miss_logic.select(item, &bucket.id);
        });

    metrics.phase4_update = t3.elapsed();
    
    metrics
}

fn main() {
    const K: usize = 40;
    const N: usize = 10;
    const ZIPF_EXP: f64 = 1.0;

    println!("{:=^60}", " OBLIVIOUS STREAM UPDATE ");
    println!("Table Size (K): {}", K);
    println!("Stream Size (N): {}", N);
    println!("------------------------------------------------------------");

    // 1. GENERATE DATA
    let stream = generate_zipf_stream(N, 50, ZIPF_EXP);
    
    // 2. PLAINTEXT BASELINE
    let mut plain_state = vec![(0u32, 0u32); K];
    for &item in &stream {
        insert_plaintext(&mut plain_state, item);
    }

    // 3. TFHE SETUP
    println!("Generating TFHE keys (this may take a moment)...");
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )
        .build();
    
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key.clone());

    let server_key_clone = server_key.clone();
    let worker_pool = rayon::ThreadPoolBuilder::new()
        .start_handler(move |_| {
            set_server_key(server_key_clone.clone());
        })
        .build()
        .unwrap();

    // 4. INITIALIZE ENCRYPTED STATE
    println!("Encrypting initial state...");
    let mut enc_state = EncryptedState {
        buckets: vec![EncryptedBucket {
            id: FheUint32::encrypt_trivial(0u32),
            count: FheUint32::encrypt_trivial(0u32),
        }; K]
    };

    // 5. OBLIVIOUS EXECUTION
    println!("Executing Oblivious Updates over {} items...", N);
    let start_time = Instant::now();
    
    let total_metrics = worker_pool.install(|| {
        let mut acc_metrics = UpdateMetrics::default();
        for (idx, &item) in stream.iter().enumerate() {
            let enc_item = FheUint32::encrypt(item, &client_key);
            let m = update_item_oblivious(&mut enc_state, &enc_item);
            acc_metrics.add(&m);
            println!("      Processed {}/{} items...", idx + 1, N);
        }
        acc_metrics
    });
    
    let merge_duration = start_time.elapsed();

    // 6. DECRYPTION & RESULTS
    let decrypted: Vec<(u32, u32)> = enc_state.buckets.iter()
        .map(|b| (b.id.decrypt(&client_key), b.count.decrypt(&client_key)))
        .collect();

    println!("\n{:=^60}", " RESULTS ");
    println!("Total Latency:    {:.2?}", merge_duration);
    println!("Avg per Item:     {:.2?}", merge_duration / N as u32);
    println!("------------------------------------------------------------");
    println!("TIMING BREAKDOWN (Accumulated):");
    println!("  Phase 1 (Hit Detection):   {:.2?}", total_metrics.phase1_hit);
    println!("  Phase 2 (Find Min):        {:.2?}", total_metrics.phase2_min);
    println!("  Phase 3 (Victim Select):   {:.2?}", total_metrics.phase3_victim);
    println!("  Phase 4 (State Update):    {:.2?}", total_metrics.phase4_update);
    println!("------------------------------------------------------------");

    let total_compute_time = total_metrics.phase1_hit + total_metrics.phase2_min 
                           + total_metrics.phase3_victim + total_metrics.phase4_update;
    
    println!("TIMING DISTRIBUTION:");
    println!("  Phase 1: {:.1}%", (total_metrics.phase1_hit.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    println!("  Phase 2: {:.1}%", (total_metrics.phase2_min.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    println!("  Phase 3: {:.1}%", (total_metrics.phase3_victim.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    println!("  Phase 4: {:.1}%", (total_metrics.phase4_update.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);

    println!("\n{:<4} {:<10} {:<10} | {:<10} {:<10} {}", "Idx", "Enc_ID", "Enc_Cnt", "Pln_ID", "Pln_Cnt", "Match");
    println!("{}", "-".repeat(60));

    let mut exact_matches = 0;
    for i in 0..K {
        let (d_id, d_cnt) = decrypted[i];
        let (p_id, p_cnt) = plain_state[i];
        
        let match_mark = if d_id == p_id && d_cnt == p_cnt { 
            exact_matches += 1; "✓" 
        } else { 
            "~" 
        };
        
        println!("{:<4} {:<10} {:<10} | {:<10} {:<10} {}", 
            i, d_id, d_cnt, p_id, p_cnt, match_mark);
    }
    
    println!("\nExact Matches: {}/{}", exact_matches, K);
}