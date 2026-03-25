use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16, FheUint32, FheUint8};
use rayon::prelude::*;
use rand::prelude::*;
use rand_distr::Zipf;
use std::time::{Duration, Instant};

// --- DATA STRUCTURES ---

// Large Table Bucket (Destination): 16-bit counts
#[derive(Clone)]
struct EncryptedBucketLarge {
    id: FheUint32,
    count: FheUint16, 
}

// Small Table Bucket (Source): 8-bit counts
#[derive(Clone)]
struct EncryptedBucketSmall {
    id: FheUint32,
    count: FheUint8,
}

struct EncryptedState {
    buckets: Vec<EncryptedBucketLarge>,
}

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

// --- HELPER FUNCTIONS ---

fn generate_zipf_stream(len: usize, max_val: u32, exponent: f64) -> Vec<u32> {
    let mut rng = thread_rng();
    let zipf = Zipf::new(max_val as u64, exponent).expect("valid zipf params");
    (0..len).map(|_| zipf.sample(&mut rng) as u32 + 1).collect()
}

// Validation logic (Plaintext SpaceSaving)
fn simulate_spacesaving(stream: &[u32], k: usize) -> Vec<(u32, u32)> {
    let mut buckets = vec![(0u32, 0u32); k];
    let mut min_val = 0u32;

    for &item in stream {
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
                if let Some((i, _)) = buckets.iter().enumerate().find(|(_, (_, cnt))| *cnt == min_val) {
                    buckets[i].0 = item;
                    buckets[i].1 += 1;
                }
            }
        }

        if let Some(min) = buckets.iter().map(|(_, cnt)| *cnt).min() {
            min_val = min;
        }
    }
    buckets
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

// --- CORE ALGORITHM: OBLIVIOUS MERGE ---

fn merge_item_oblivious(
    large: &mut EncryptedState,
    item: &FheUint32,
    freq: &FheUint8,
) -> MergeMetrics {
    let mut metrics = MergeMetrics::default();

    // Cast 8-bit frequency to 16-bit to match large table
    // (Cast is a local operation or cheap keyswitch depending on params, relatively fast)
    // let freq_u16: FheUint16 = freq.cast_into();
    // Clone the reference to get an owned FheUint8, then cast
    let freq_u16: FheUint16 = freq.clone().cast_into();
    // --- PHASE 1: HIT DETECTION ---
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
    let t1 = Instant::now();
    
    // 1. Prepare inputs: Pair (Count, Index)
    // Counts are FheUint16. Indices are FheUint8 (since 30 buckets < 255).
    let indexed_counts: Vec<(FheUint16, FheUint8)> = large.buckets.par_iter().enumerate()
        .map(|(i, b)| {
            (b.count.clone(), FheUint8::encrypt_trivial(i as u8))
        })
        .collect();

    // 2. Run Reduction
    let (min_val, victim_idx) = indexed_counts.par_chunks(4)
        .map(|chunk| {
            let mut local_best = chunk[0].clone();
            for next in &chunk[1..] {
                let (best_val, best_idx) = &local_best;
                let (curr_val, curr_idx) = next;
                
                let pick_new = curr_val.lt(best_val); 
                
                local_best = (
                    pick_new.select(curr_val, best_val),
                    pick_new.select(curr_idx, best_idx)
                );
            }
            local_best
        })
        .reduce(
            || (FheUint16::encrypt_trivial(u16::MAX), FheUint8::encrypt_trivial(255u8)),
            | (val_a, idx_a), (val_b, idx_b) | {
                let pick_a = val_a.le(&val_b); 
                (
                    pick_a.select(&val_a, &val_b), 
                    pick_a.select(&idx_a, &idx_b) 
                )
            }
        );
    metrics.phase2_min = t1.elapsed();

    // --- PHASE 3: CHEAP MASK GENERATION ---
    let t2 = Instant::now();
    let victim_mask: Vec<FheBool> = (0..large.buckets.len()).into_par_iter()
        .map(|i| victim_idx.eq(i as u8))
        .collect();
    metrics.phase3_victim = t2.elapsed();

    // --- PHASE 4: UNIFIED UPDATE ---
    let t3 = Instant::now();

    // 1. Hoisting
    let val_if_victim_global = &min_val + &freq_u16;
    let not_found = !&found;

    // 2. Chunking & Zipping
    large.buckets.par_chunks_mut(4)
        .zip(hits.par_chunks(4))
        .zip(victim_mask.par_chunks(4))
        .for_each(|((bucket_chunk, hit_chunk), mask_chunk)| {
            for i in 0..bucket_chunk.len() {
                let bucket = &mut bucket_chunk[i];
                let is_hit = &hit_chunk[i];
                let is_victim_ptr = &mask_chunk[i];

                let is_victim_miss = is_victim_ptr & &not_found;

                // A. Hit Value (u16 + u16)
                let val_if_hit = &bucket.count + &freq_u16;

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

// --- MAIN EXECUTION ---

fn main() {
    // --- EXPERIMENT CONFIGURATION ---
    const LARGE_K: usize = 30; // M = 30
    const SMALL_K: usize = 20; // N = 20
    const ZIPF_EXP: f64 = 1.2;
    
    // Stream sizes adjusted to prevent overflow on u8/u16
    // u8 max is 255. A small stream of 100 ensures counts stay low for the small table.
    // u16 max is 65535. Large stream + merge will fit easily.
    const LARGE_STREAM: usize = 2000; 
    const SMALL_STREAM: usize = 200;  

    println!("{:=^60}", " OBLIVIOUS SPACESAVING (Mixed Precision) ");
    println!("Large Table (M): {} buckets (16-bit counts)", LARGE_K);
    println!("Small Table (N): {} buckets (8-bit counts)", SMALL_K);
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

    // Validate no overflow in plaintext before encryption
    if plain_small.iter().any(|(_, c)| *c > 255) {
        panic!("Error: Small table counts exceeded 8-bit limit (255)!");
    }
    if expected_merged.iter().any(|(_, c)| *c > 65535) {
        panic!("Error: Merged counts exceeded 16-bit limit (65535)!");
    }

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
    
    // Encrypt Large (FheUint16 for count)
    let mut enc_large = EncryptedState {
        buckets: plain_large.iter().map(|(id, cnt)| EncryptedBucketLarge {
            id: FheUint32::encrypt(*id, &client_key),
            count: FheUint16::encrypt(*cnt as u16, &client_key),
        }).collect(),
    };

    // Encrypt Small (FheUint8 for count)
    let enc_small: Vec<EncryptedBucketSmall> = plain_small.iter().map(|(id, cnt)| EncryptedBucketSmall {
        id: FheUint32::encrypt(*id, &client_key),
        count: FheUint8::encrypt(*cnt as u8, &client_key),
    }).collect();

    // 5. OBLIVIOUS MERGE EXECUTION
    println!("[5/6] Executing Oblivious Merge...");
    let start_time = Instant::now();
    
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
    // let decrypted: Vec<(u32, u32)> = enc_large.buckets.iter()
    //     .map(|b| (b.id.decrypt(&client_key), b.count.decrypt(&client_key) as u32))
    //     .collect();
    // let decrypted: Vec<(u32, u32)> = enc_large.buckets.iter()
    // .map(|b| (
    //     b.id.decrypt(&client_key), 
    //     // Explicitly specify ::<u16> before casting to u32
    //     b.count.decrypt::<u16>(&client_key) as u32
    // ))
    // .collect();

    // Replace the entire decryption block with this:
    let decrypted: Vec<(u32, u32)> = enc_large.buckets.iter()
        .map(|b| {
            // 1. Decrypt ID (u32)
            let id: u32 = b.id.decrypt(&client_key);
            
            // 2. Decrypt Count (explicitly as u16, then cast to u32)
            let count: u16 = b.count.decrypt(&client_key);
            
            (id, count as u32)
        })
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