use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32, FheUint8};
use rayon::prelude::*;
use rand::prelude::*;
use rand_distr::Zipf;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct EncryptedBucket {
    id: FheUint32,
    count: FheUint32,
}

struct EncryptedState {
    buckets: Vec<EncryptedBucket>,
    #[allow(dead_code)]
    zero: FheUint32,
}

// --- NEW: Struct to hold timing metrics for a single merge operation ---
#[derive(Debug, Default, Clone, Copy)]
struct MergeMetrics {
    phase1_hit: Duration,
    phase2_min: Duration,
    phase3_victim: Duration,
    phase4_update: Duration,
}

impl MergeMetrics {
    fn add(&mut self, other: &MergeMetrics) {
        self.phase1_hit += other.phase1_hit;
        self.phase2_min += other.phase2_min;
        self.phase3_victim += other.phase3_victim;
        self.phase4_update += other.phase4_update;
    }
}

// Oblivious First-1 (leftmost) with fixed circuit depth
fn first_one(cands: &[FheBool]) -> Vec<FheBool> {
    let mut out = Vec::with_capacity(cands.len());
    let mut seen = FheBool::encrypt_trivial(false);
    for c in cands {
        let selected = c & !&seen;
        seen = &seen | c;
        out.push(selected);
    }
    out
}

// CORRECT SpaceSaving simulation (plaintext) for validation
fn simulate_spacesaving(stream: &[u32], k: usize) -> Vec<(u32, u32)> {
    let mut buckets = vec![(0u32, 0u32); k]; // (id, count)
    let mut min_val = 0u32;

    for &item in stream {
        // Hit detection
        let mut hit_idx = None;
        for (i, (id, _)) in buckets.iter().enumerate() {
            if *id == item && *id != 0 { // ID=0 reserved for empty
                hit_idx = Some(i);
                break;
            }
        }

        match hit_idx {
            Some(i) => buckets[i].1 += 1, // Hit: increment
            None => {
                // Miss: find first bucket at min_val
                if let Some((i, _)) = buckets.iter().enumerate().find(|(_, (_, cnt))| *cnt == min_val) {
                    buckets[i].0 = item;
                    buckets[i].1 += 1;
                }
            }
        }

        // Update min_val
        if let Some(min) = buckets.iter().map(|(_, cnt)| *cnt).min() {
            min_val = min;
        }
    }
    buckets
}

fn generate_zipf_stream(len: usize, max_val: u32, exponent: f64) -> Vec<u32> {
    let mut rng = thread_rng();
    let zipf = Zipf::new(max_val as u64, exponent).expect("valid zipf params");
    (0..len).map(|_| zipf.sample(&mut rng) as u32 + 1).collect()
}

/*
// --- MODIFIED: Returns MergeMetrics instead of () ---
fn merge_item_oblivious(
    large: &mut EncryptedState,
    item: &FheUint32,
    freq: &FheUint32,
) -> MergeMetrics {
    let mut metrics = MergeMetrics::default();

    // PHASE 1: Hit detection (broadcast equality)
    let t0 = Instant::now();
    let hits: Vec<FheBool> = large.buckets.par_iter()
        .map(|b| b.id.eq(item))
        .collect();
    // let hits: Vec<FheBool> = large.buckets.par_chunks(4) // Process 4 buckets per thread
    // .flat_map(|chunk| {
    //     chunk.iter().map(|b| b.id.eq(item)).collect::<Vec<_>>()
    // })
    // .collect();

    let found = hits.par_iter()
        .cloned()
        .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    metrics.phase1_hit = t0.elapsed();

    // PHASE 2: Find global minimum via Parallel Reduction Tree
    let t1 = Instant::now();
    // let min_val = large.buckets.par_iter()
    //     .map(|b| b.count.clone())
    //     .reduce(
    //         || FheUint32::encrypt_trivial(u32::MAX), 
    //         |a, b| a.min(&b) 
    //     );

    // Strategy: Use chunks to reduce Rayon synchronization overhead.
    // A chunk size of 4-8 is often the sweet spot for FHE integer ops.
    let min_val = large.buckets.par_chunks(4) 
        .map(|chunk| {
            // 1. Sequential reduction inside the chunk (very fast, no thread overhead)
            // We initialize with the first element to avoid an extra MAX encrypt
            let mut local_min = chunk[0].count.clone();
            for bucket in &chunk[1..] {
                local_min = local_min.min(&bucket.count);
            }
            local_min
        })
        // 2. Parallel reduction of the chunk results
        .reduce(
            || FheUint32::encrypt_trivial(u32::MAX), 
            |a, b| a.min(&b)
        );
    
    metrics.phase2_min = t1.elapsed();

    // PHASE 3: Victim selection
    let t2 = Instant::now();
    let is_min: Vec<FheBool> = large.buckets.par_iter()
        .map(|b| b.count.eq(&min_val))
        .collect();
    
    let victim_mask = first_one(&is_min);
    metrics.phase3_victim = t2.elapsed();

    // PHASE 4: Unified State Update
    // let t3 = Instant::now();
    // large.buckets.par_iter_mut().enumerate().for_each(|(i, bucket)| {
    //     let is_hit = &hits[i];
        
    //     let is_victim_miss = &victim_mask[i] & !&found;

    //     // CALCULATE NEW VALUES
    //     let val_if_hit = &bucket.count + freq;
    //     let val_if_victim = &min_val + freq;
        
    //     // MUX Logic
    //     let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);
    //     bucket.count = is_victim_miss.select(&val_if_victim, &after_hit_check);

    //     // ID UPDATE
    //     bucket.id = is_victim_miss.select(item, &bucket.id);
    // });
    // metrics.phase4_update = t3.elapsed();
    let t3 = Instant::now();

    // 1. HOISTING: Calculate loop-invariant values ONCE.
    // Optimization: Saves 49 expensive encrypted additions (for K=50)
    let val_if_victim_global = &min_val + freq;
    let not_found = !&found;

    // 2. CHUNKING & ZIPPING:
    // Process 4 buckets at a time to amortize thread overhead.
    // We zip the buckets with their corresponding hit/mask flags to avoid manual indexing.
    large.buckets.par_chunks_mut(4)
        .zip(hits.par_chunks(4))
        .zip(victim_mask.par_chunks(4))
        .for_each(|((bucket_chunk, hit_chunk), mask_chunk)| {
            
            // Sequential processing inside the thread (very fast context switching)
            for i in 0..bucket_chunk.len() {
                let bucket = &mut bucket_chunk[i];
                let is_hit = &hit_chunk[i];
                let is_victim_ptr = &mask_chunk[i];

                // Optimization: Compute condition locally
                // Note: We use the HOISTED 'not_found' here
                let is_victim_miss = is_victim_ptr & &not_found;

                // --- UNIFIED UPDATE LOGIC ---

                // A. Calculate Hit Value
                // (Must be done per bucket because 'count' varies)
                let val_if_hit = &bucket.count + freq;

                // B. MUX Logic
                // 1. If Hit -> (Count + Freq)
                //    Else   -> (Count)
                let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);

                // 2. If Victim Miss -> (Min + Freq) [USING HOISTED VALUE]
                //    Else           -> (Result of Step 1)
                bucket.count = is_victim_miss.select(&val_if_victim_global, &after_hit_check);

                // C. ID Update
                bucket.id = is_victim_miss.select(item, &bucket.id);
            }
        });

    metrics.phase4_update = t3.elapsed();

    metrics
}
*/
fn merge_item_oblivious(
    large: &mut EncryptedState,
    item: &FheUint32,
    freq: &FheUint32,
) -> MergeMetrics {
    let mut metrics = MergeMetrics::default();

    // --- PHASE 1: HIT DETECTION (Chunked) ---
    let t0 = Instant::now();
    let hits: Vec<FheBool> = large.buckets.par_chunks(4)
        .flat_map(|chunk| {
            chunk.iter().map(|b| b.id.eq(item)).collect::<Vec<_>>()
        })
        .collect();
    
    let found = hits.par_iter().cloned()
        .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    metrics.phase1_hit = t0.elapsed();

    // --- PHASE 2: AUGMENTED MIN REDUCTION ---
    // Goal: Find (MinCount, MinIndex) in one pass.
    // This replaces the old "Find Min -> Scan Equality -> First-One" pipeline.
    let t1 = Instant::now();
    
    // 1. Prepare inputs: Pair (Count, Index)
    // We use trivial encryption for indices because they are public constants (0..K)
    let indexed_counts: Vec<(FheUint32, FheUint8)> = large.buckets.par_iter().enumerate()
        .map(|(i, b)| {
            (b.count.clone(), FheUint8::encrypt_trivial(i as u8))
        })
        .collect();

    // 2. Run Reduction (Chunked for performance)
    let (min_val, victim_idx) = indexed_counts.par_chunks(4)
        .map(|chunk| {
            // Sequential reduction inside chunk
            let mut local_best = chunk[0].clone();
            for next in &chunk[1..] {
                let (best_val, best_idx) = &local_best;
                let (curr_val, curr_idx) = next;
                
                // "Less Equal" ensures stability (tie-break left)
                let pick_new = curr_val.lt(best_val); 
                
                local_best = (
                    pick_new.select(curr_val, best_val),
                    pick_new.select(curr_idx, best_idx)
                );
            }
            local_best
        })
        .reduce(
            || (FheUint32::encrypt_trivial(u32::MAX), FheUint8::encrypt_trivial(255u8)),
            | (val_a, idx_a), (val_b, idx_b) | {
                // Tie-breaking logic: If values equal, prefer lower index (A)
                let pick_a = val_a.le(&val_b); 
                
                (
                    pick_a.select(&val_a, &val_b), 
                    pick_a.select(&idx_a, &idx_b) 
                )
            }
        );
    metrics.phase2_min = t1.elapsed();

    // --- PHASE 3: CHEAP MASK GENERATION ---
    // Optimization: Compare 8-bit indices instead of 32-bit counts.
    // Speedup: ~4x faster than the previous equality scan.
    let t2 = Instant::now();
    let victim_mask: Vec<FheBool> = (0..large.buckets.len()).into_par_iter()
        .map(|i| {
            // We compare the encrypted victim_idx against constant i
            victim_idx.eq(i as u8) 
        })
        .collect();
    metrics.phase3_victim = t2.elapsed();

    // --- PHASE 4: UNIFIED UPDATE (Hoisted & Chunked) ---
    let t3 = Instant::now();

    // 1. HOISTING: Calculate loop-invariant values ONCE.
    let val_if_victim_global = &min_val + freq;
    let not_found = !&found;

    // 2. CHUNKING & ZIPPING
    large.buckets.par_chunks_mut(4)
        .zip(hits.par_chunks(4))
        .zip(victim_mask.par_chunks(4))
        .for_each(|((bucket_chunk, hit_chunk), mask_chunk)| {
            for i in 0..bucket_chunk.len() {
                let bucket = &mut bucket_chunk[i];
                let is_hit = &hit_chunk[i];
                let is_victim_ptr = &mask_chunk[i];

                let is_victim_miss = is_victim_ptr & &not_found;

                // A. Hit Value
                let val_if_hit = &bucket.count + freq;

                // B. MUX Logic
                let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);
                bucket.count = is_victim_miss.select(&val_if_victim_global, &after_hit_check);

                // C. ID Update
                bucket.id = is_victim_miss.select(item, &bucket.id);
            }
        });

    metrics.phase4_update = t3.elapsed();

    metrics
}

fn merge_plaintext(large: &[(u32, u32)], small: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut merged = large.to_vec();
    let get_min = |b: &[(u32, u32)]| b.iter().map(|(_, c)| *c).min().unwrap_or(0);
    let mut min_val = get_min(&merged);

    for &(small_id, small_freq) in small {
        if small_freq == 0 { continue; }

        let mut hit = false;
        for (id, count) in &mut merged {
            if *id == small_id && *id != 0 {
                *count += small_freq;
                hit = true;
                break;
            }
        }

        if !hit {
            if let Some((id, count)) = merged.iter_mut().find(|(_, c)| *c == min_val) {
                *id = small_id;
                *count = min_val + small_freq; 
            }
        }
        min_val = get_min(&merged);
    }
    merged
}

fn main() {
    // --- EXPERIMENT CONFIGURATION ---
    const LARGE_K: usize = 50;
    const SMALL_K: usize = 5;
    const ZIPF_EXP: f64 = 1.2;
    const LARGE_STREAM: usize = 5000;
    const SMALL_STREAM: usize = 1500;

    println!("{:=^60}", " OBLIVIOUS SPACESAVING MERGE ");
    println!("Large Table Size: {}", LARGE_K);
    println!("Small Table Size: {}", SMALL_K);
    println!("Zipf Exponent:    {}", ZIPF_EXP);
    println!("------------------------------------------------------------");

    // 1. DATA GENERATION
    println!("[1/6] Generating Zipfian streams...");
    let large_stream = generate_zipf_stream(LARGE_STREAM, 200, ZIPF_EXP);
    let small_stream = generate_zipf_stream(SMALL_STREAM, 200, ZIPF_EXP);

    // 2. BASELINE GENERATION
    println!("[2/6] Building plaintext summaries...");
    let plain_large = simulate_spacesaving(&large_stream, LARGE_K);
    let plain_small = simulate_spacesaving(&small_stream, SMALL_K);
    let expected_merged = merge_plaintext(&plain_large, &plain_small);

    // 3. TFHE SETUP
    println!("[3/6] Generating TFHE keys...");
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )
        .build();
    
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key.clone());

    let server_key_clone = server_key.clone();
    let worker_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8) 
        .start_handler(move |_| {
            set_server_key(server_key_clone.clone());
        })
        .build()
        .unwrap();

    // 4. ENCRYPTION
    println!("[4/6] Encrypting tables...");
    let encrypt_bucket = |(id, cnt): &(u32, u32)| EncryptedBucket {
        id: FheUint32::encrypt(*id, &client_key),
        count: FheUint32::encrypt(*cnt, &client_key),
    };

    let mut enc_large = EncryptedState {
        buckets: plain_large.iter().map(encrypt_bucket).collect(),
        zero: FheUint32::encrypt_trivial(0u32),
    };

    let enc_small: Vec<EncryptedBucket> = plain_small.iter().map(encrypt_bucket).collect();

    // 5. OBLIVIOUS MERGE EXECUTION
    println!("[5/6] Executing Oblivious Merge...");
    let start_time = Instant::now();
    
    // Captured metrics accumulator
    let total_metrics = worker_pool.install(|| {
        let mut acc_metrics = MergeMetrics::default();
        for (idx, bucket) in enc_small.iter().enumerate() {
            let m = merge_item_oblivious(&mut enc_large, &bucket.id, &bucket.count);
            acc_metrics.add(&m);
            
            if (idx + 1) % 5 == 0 {
                println!("      Processed {}/{} buckets...", idx + 1, SMALL_K);
            }
        }
        acc_metrics
    });
    
    let merge_duration = start_time.elapsed();
    println!("      Merge finished in {:.2?}", merge_duration);

    // 6. DECRYPTION & VALIDATION
    println!("[6/6] Decrypting and Validating results...");
    let decrypted: Vec<(u32, u32)> = enc_large.buckets.iter()
        .map(|b| (b.id.decrypt(&client_key), b.count.decrypt(&client_key)))
        .collect();

    let mut decrypted_sorted = decrypted.clone();
    decrypted_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    
    let mut expected_sorted = expected_merged.clone();
    expected_sorted.sort_by(|a, b| b.1.cmp(&a.1));

    println!("\n{:=^60}", " RESULTS ");
    println!("Total Latency:    {:.2?}", merge_duration);
    println!("Avg per Item:     {:.2?}", merge_duration / SMALL_K as u32);
    println!("------------------------------------------------------------");
    println!("TIMING BREAKDOWN (Accumulated):");
    println!("  Phase 1 (Hit Detection):   {:.2?}", total_metrics.phase1_hit);
    println!("  Phase 2 (Find Min):        {:.2?}", total_metrics.phase2_min);
    println!("  Phase 3 (Victim Select):   {:.2?}", total_metrics.phase3_victim);
    println!("  Phase 4 (State Update):    {:.2?}", total_metrics.phase4_update);
    println!("------------------------------------------------------------");
    
    // Percentage Calculation
    let total_compute_time = total_metrics.phase1_hit + total_metrics.phase2_min 
                           + total_metrics.phase3_victim + total_metrics.phase4_update;
    
    println!("TIMING DISTRIBUTION:");
    println!("  Phase 1: {:.1}%", (total_metrics.phase1_hit.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    println!("  Phase 2: {:.1}%", (total_metrics.phase2_min.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    println!("  Phase 3: {:.1}%", (total_metrics.phase3_victim.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    println!("  Phase 4: {:.1}%", (total_metrics.phase4_update.as_secs_f64() / total_compute_time.as_secs_f64()) * 100.0);
    
    println!("{}", "-".repeat(60));
    println!("{:<4} {:<10} {:<10} | {:<10} {:<10} {}", "Rank", "ID", "Count", "Exp_ID", "Exp_Cnt", "Match");
    println!("{}", "-".repeat(60));

    let top_k_display = 10;
    let mut exact_matches = 0;
    
    for i in 0..top_k_display {
        let (d_id, d_cnt) = decrypted_sorted[i];
        let (e_id, e_cnt) = expected_sorted[i];
        
        let match_mark = if d_id == e_id && d_cnt == e_cnt { 
            exact_matches += 1; "✓" 
        } else { 
            "~" 
        };
        
        println!("{:<4} {:<10} {:<10} | {:<10} {:<10} {}", 
            i+1, d_id, d_cnt, e_id, e_cnt, match_mark);
    }
    
    println!("\nExact Matches in Top {}: {}/{}", top_k_display, exact_matches, top_k_display);
    
    let total_freq_decrypted: u64 = decrypted.iter().map(|(_,c)| *c as u64).sum();
    let total_freq_expected: u64 = expected_merged.iter().map(|(_,c)| *c as u64).sum();

    println!("\nTotal Frequency Preserved: {} / {}", total_freq_decrypted, total_freq_expected);
}