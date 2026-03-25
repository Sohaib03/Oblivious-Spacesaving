use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32, FheUint16, FheUint8};
use rayon::prelude::*;
use rand::prelude::*;
use rand_distr::Zipf;
use rand_distr::Distribution;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct EncryptedBucket {
    id: FheUint32,
    count: FheUint16, // 16-bit counter
}

struct EncryptedState {
    buckets: Vec<EncryptedBucket>,
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

// ----------------------------------------------------------------------------
// PLAINTEXT BASELINES (For Validation)
// ----------------------------------------------------------------------------

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

// Plaintext logic for merging a small summary into a large summary
fn merge_plaintext(large: &[(u32, u32)], small: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut merged = large.to_vec();
    
    for &(item, freq) in small {
        if item == 0 || freq == 0 { continue; } // Skip empty buckets

        let mut hit_idx = None;
        for (i, (id, _)) in merged.iter().enumerate() {
            if *id == item && *id != 0 {
                hit_idx = Some(i);
                break;
            }
        }

        match hit_idx {
            Some(i) => merged[i].1 += freq, // Hit: Add frequency
            None => {
                // Miss: Find min and replace
                let min_val = merged.iter().map(|(_, cnt)| *cnt).min().unwrap_or(0);
                if let Some((i, _)) = merged.iter().enumerate().find(|(_, (_, cnt))| *cnt == min_val) {
                    merged[i].0 = item;
                    merged[i].1 = min_val + freq;
                }
            }
        }
    }
    merged
}

fn generate_zipf_stream(len: usize, max_val: u32, exponent: f64) -> Vec<u32> {
    let mut rng = thread_rng();
    let zipf = Zipf::new(max_val as u64, exponent).expect("valid zipf params");
    (0..len).map(|_| zipf.sample(&mut rng) as u32 + 1).collect()
}

// ----------------------------------------------------------------------------
// OBLIVIOUS MERGE LOGIC
// ----------------------------------------------------------------------------

// Merges a single (ID, Freq) pair into the target encrypted state
fn merge_item_oblivious(
    state: &mut EncryptedState,
    item: &FheUint32,
    freq: &FheUint16, // Variable frequency from the small table
) -> MergeMetrics {
    let mut metrics = MergeMetrics::default();

    // --- PHASE 1: HIT DETECTION ---
    let t0 = Instant::now();
    let hits: Vec<FheBool> = state.buckets.par_iter()
        .map(|b| b.id.eq(item))
        .collect();
    
    let found = hits.par_iter().cloned()
        .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    metrics.phase1_hit = t0.elapsed();

    // --- PHASE 2: AUGMENTED MIN REDUCTION (16-bit) ---
    let t1 = Instant::now();
    let indexed_counts: Vec<(FheUint16, FheUint8)> = state.buckets.par_iter().enumerate()
        .map(|(i, b)| {
            (b.count.clone(), FheUint8::encrypt_trivial(i as u8))
        })
        .collect();

    let (min_val, victim_idx) = indexed_counts.par_iter()
        .cloned() 
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
    let victim_mask: Vec<FheBool> = (0..state.buckets.len()).into_par_iter()
        .map(|i| {
            victim_idx.eq(i as u8) 
        })
        .collect();
    metrics.phase3_victim = t2.elapsed();

    // --- PHASE 4: UNIFIED UPDATE ---
    let t3 = Instant::now();

    // 1. Calculate values
    let val_if_victim_global = &min_val + freq;
    
    // 2. NEW LOGIC: Prevent overwrites from empty buckets (freq == 0)
    let zero_freq = FheUint16::encrypt_trivial(0u16);
    let is_non_zero_freq = freq.ne(&zero_freq);
    let not_found = !&found;
    
    // A miss is only valid if we didn't find the item AND the incoming freq is > 0
    let valid_miss = not_found & is_non_zero_freq;

    state.buckets.par_iter_mut()
        .zip(hits.par_iter())
        .zip(victim_mask.par_iter())
        .for_each(|((bucket, is_hit), is_victim_ptr)| {
            
            // Use valid_miss instead of not_found
            let is_victim_miss = is_victim_ptr & &valid_miss;

            // Hit Value: Count is increased by `freq`
            // (If freq == 0, this adds 0 to the count, which is a safe no-op)
            let val_if_hit = &bucket.count + freq;
            
            // MUX Logic for the count
            let after_hit_check = is_hit.select(&val_if_hit, &bucket.count);
            bucket.count = is_victim_miss.select(&val_if_victim_global, &after_hit_check);

            // MUX Logic for ID Overwrite
            // Because valid_miss is false when freq == 0, is_victim_miss is false, 
            // and the ID is safely preserved.
            bucket.id = is_victim_miss.select(item, &bucket.id);
        });

    metrics.phase4_update = t3.elapsed();
    metrics
}

// Wrapper function to iterate over the small state and merge it into the large state
fn merge_encrypted_states(
    large_state: &mut EncryptedState,
    small_state: &EncryptedState,
) -> MergeMetrics {
    let mut total_metrics = MergeMetrics::default();
    
    // Process each bucket from the small summary sequentially
    for (idx, bucket) in small_state.buckets.iter().enumerate() {
        // Optimization: We could technically add a homomorphic check here to skip 
        // completely empty buckets (ID=0), but for constant-time benchmarking, 
        // we process every bucket in the small table.
        let m = merge_item_oblivious(large_state, &bucket.id, &bucket.count);
        total_metrics.add(&m);
        
        println!("      Merged bucket {}/{}...", idx + 1, small_state.buckets.len());
    }
    total_metrics
}

// ----------------------------------------------------------------------------
// MAIN EXECUTION
// ----------------------------------------------------------------------------

fn main() {
    const LARGE_K: usize = 40;
    const SMALL_K: usize = 40;
    const ZIPF_EXP: f64 = 1.0;

    println!("{:=^60}", " OBLIVIOUS TABLE MERGE ");
    println!("Large Table (K): {}", LARGE_K);
    println!("Small Table (K): {}", SMALL_K);
    println!("------------------------------------------------------------");

    // 1. GENERATE DATA STREAMS
    println!("Generating mock data streams...");
    let stream_large = generate_zipf_stream(100, 50, ZIPF_EXP);
    let stream_small = generate_zipf_stream(30, 50, ZIPF_EXP);
    
    // 2. PLAINTEXT BASELINES
    let mut plain_large = vec![(0u32, 0u32); LARGE_K];
    for &item in &stream_large { insert_plaintext(&mut plain_large, item); }

    let mut plain_small = vec![(0u32, 0u32); SMALL_K];
    for &item in &stream_small { insert_plaintext(&mut plain_small, item); }

    let expected_merged = merge_plaintext(&plain_large, &plain_small);

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

    // 4. ENCRYPT INITIAL STATES
    println!("Encrypting large and small state tables...");
    let encrypt_bucket = |(id, count): &(u32, u32)| EncryptedBucket {
        id: FheUint32::encrypt(*id, &client_key),
        count: FheUint16::encrypt(*count as u16, &client_key),
    };

    let mut enc_large = EncryptedState {
        buckets: plain_large.iter().map(encrypt_bucket).collect(),
    };
    
    let enc_small = EncryptedState {
        buckets: plain_small.iter().map(encrypt_bucket).collect(),
    };

    // 5. OBLIVIOUS EXECUTION
    println!("Executing Oblivious Merge into Large State...");
    let start_time = Instant::now();
    
    let total_metrics = worker_pool.install(|| {
        merge_encrypted_states(&mut enc_large, &enc_small)
    });
    
    let merge_duration = start_time.elapsed();

    // 6. DECRYPTION & RESULTS
    let decrypted: Vec<(u32, u32)> = enc_large.buckets.iter()
        .map(|b| {
            let id: u32 = b.id.decrypt(&client_key);
            let count_u16: u16 = b.count.decrypt(&client_key);
            (id, count_u16 as u32) 
        })
        .collect();

    println!("\n{:=^60}", " RESULTS ");
    println!("Total Merge Time: {:.2?}", merge_duration);
    println!("Avg Time per Bucket Merged: {:.2?}", merge_duration / SMALL_K as u32);
    println!("------------------------------------------------------------");
    println!("TIMING BREAKDOWN (Accumulated over {} merges):", SMALL_K);
    println!("  Phase 1 (Hit Detection):   {:.2?}", total_metrics.phase1_hit);
    println!("  Phase 2 (Find Min):        {:.2?}", total_metrics.phase2_min);
    println!("  Phase 3 (Victim Select):   {:.2?}", total_metrics.phase3_victim);
    println!("  Phase 4 (State Update):    {:.2?}", total_metrics.phase4_update);
    println!("------------------------------------------------------------");

    println!("\n{:<4} {:<10} {:<10} | {:<10} {:<10} {}", "Idx", "Enc_ID", "Enc_Cnt", "Pln_ID", "Pln_Cnt", "Match");
    println!("{}", "-".repeat(60));

    let mut exact_matches = 0;
    for i in 0..LARGE_K {
        let (d_id, d_cnt) = decrypted[i];
        let (p_id, p_cnt) = expected_merged[i];
        
        let match_mark = if d_id == p_id && d_cnt == p_cnt { 
            exact_matches += 1; "✓" 
        } else { 
            "~" 
        };
        
        println!("{:<4} {:<10} {:<10} | {:<10} {:<10} {}", 
            i, d_id, d_cnt, p_id, p_cnt, match_mark);
    }
    
    println!("\nExact Matches: {}/{}", exact_matches, LARGE_K);
}