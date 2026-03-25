use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::{Instant, Duration};
use std::env;
use tfhe::shortint::parameters::v1_0::V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

// --- DATA STRUCTURES ---

#[derive(Clone)]
struct EncryptedBucket {
    id: FheUint32,
    count: FheUint32,
}

struct EncryptedState {
    buckets: Vec<EncryptedBucket>,
    min_val: FheUint32,
    constants: (FheUint32, FheUint32), // (zero, one)
}

// 1. STRUCT: To hold timing data
#[derive(Debug, Default)]
struct StepProfiler {
    hit_detection: Duration,
    victim_selection: Duration,
    state_update: Duration,
    floor_maintenance: Duration,
    count: u32,
}

// --- OBLIVIOUS ALGORITHMS ---

// fn process_packet_oblivious(state: &mut EncryptedState, item: &FheUint32, profiler: &mut StepProfiler) {

//     let (zero, one) = &state.constants;

//     // --- STEP 1: HIT DETECTION ---
//     let t0 = Instant::now();
    
//     let is_match: Vec<FheBool> = state.buckets.par_iter()
//         .map(|bucket| bucket.id.eq(item))
//         .collect();

//     let found_any = is_match.par_iter()
//         .cloned()
//         .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    
//     profiler.hit_detection += t0.elapsed();


//     // --- STEP 2: VICTIM SELECTION ---
//     let t1 = Instant::now();
    
//     let is_min: Vec<FheBool> = state.buckets.par_iter()
//         .map(|bucket| bucket.count.eq(&state.min_val))
//         .collect();

//     // Changed: dynamic capacity based on actual buckets len
//     let mut victim_mask = Vec::with_capacity(state.buckets.len());
//     let mut seen_first = FheBool::encrypt_trivial(false);

//     for is_candidate in &is_min {
//         let selected = is_candidate & !&seen_first;
//         seen_first |= is_candidate;
//         victim_mask.push(selected);
//     }
    
//     profiler.victim_selection += t1.elapsed();


//     // --- STEP 3: STATE UPDATE ---
//     let t2 = Instant::now();
    
//     state.buckets.par_iter_mut()
//         .enumerate()
//         .for_each(|(i, bucket)| {
//             let hit_logic = &is_match[i];
//             let miss_logic = &victim_mask[i] & !&found_any;
            
//             // Optimization: Combine flags for the counter update
//             let do_increment = hit_logic | &miss_logic;
//             // let increment: FheUint32 = do_increment.cast_into();
//             let increment = do_increment.select(one, zero);
            
//             // Update Count (Add 0 or 1)
//             bucket.count = &bucket.count + &increment;
            
//             // Update ID (Must use Select/Mux)
//             bucket.id = miss_logic.select(item, &bucket.id);
//         });
    
//     profiler.state_update += t2.elapsed();


//     // --- STEP 4: FLOOR MAINTENANCE ---
//     let t3 = Instant::now();
    
//     let any_at_floor = state.buckets.par_iter()
//         .map(|bucket| bucket.count.eq(&state.min_val))
//         .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);

//     // let increment: FheUint32 = (!any_at_floor).cast_into();
//     let increment = (!any_at_floor).select(one, zero);
//     state.min_val = &state.min_val + increment;
    
//     profiler.floor_maintenance += t3.elapsed();
    
//     // Increment total items processed
//     profiler.count += 1;
// }

// Helper function for O(log N) depth parallel first-one evaluation
fn parallel_first_one(cands: &[FheBool]) -> (Vec<FheBool>, FheBool) {
    let len = cands.len();
    if len == 0 {
        return (Vec::new(), FheBool::encrypt_trivial(false));
    }
    if len == 1 {
        return (vec![cands[0].clone()], cands[0].clone());
    }

    let mid = len / 2;
    
    // Process left and right halves in parallel using Rayon's work-stealing
    let ((mut left_mask, left_any), (right_mask, right_any)) = rayon::join(
        || parallel_first_one(&cands[..mid]),
        || parallel_first_one(&cands[mid..])
    );

    // The right side is only valid if NOTHING was found in the left side
    let not_left_any = !&left_any;
    
    // In parallel, mask out the right side if the left side had a match
    let masked_right: Vec<FheBool> = right_mask.par_iter()
        .map(|r| r & &not_left_any)
        .collect();
        
    // Combine the masks
    left_mask.extend(masked_right);
    
    // Boolean OR to determine if any true value was found in this subtree
    let combined_any = left_any | &right_any;

    (left_mask, combined_any)
}

fn process_packet_oblivious(state: &mut EncryptedState, item: &FheUint32, profiler: &mut StepProfiler) {

    let (zero, one) = &state.constants;

    // --- STEP 1: HIT DETECTION ---
    let t0 = Instant::now();
    
    let is_match: Vec<FheBool> = state.buckets.par_iter()
        .map(|bucket| bucket.id.eq(item))
        .collect();

    let found_any = is_match.par_iter()
        .cloned()
        .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);
    
    profiler.hit_detection += t0.elapsed();


    // --- STEP 2: VICTIM SELECTION (Parallel Tree Optimization) ---
    let t1 = Instant::now();
    
    let is_min: Vec<FheBool> = state.buckets.par_iter()
        .map(|bucket| bucket.count.eq(&state.min_val))
        .collect();

    // Replaced the O(N) sequential loop with an O(log N) parallel divide-and-conquer tree
    let (victim_mask, _) = parallel_first_one(&is_min);
    
    profiler.victim_selection += t1.elapsed();


    // --- STEP 3: STATE UPDATE ---
    let t2 = Instant::now();
    
    state.buckets.par_iter_mut()
        .enumerate()
        .for_each(|(i, bucket)| {
            let hit_logic = &is_match[i];
            let miss_logic = &victim_mask[i] & !&found_any;
            
            // Optimization: Combine flags for the counter update
            let do_increment = hit_logic | &miss_logic;
            let increment = do_increment.select(one, zero);
            
            // Update Count (Add 0 or 1)
            bucket.count = &bucket.count + &increment;
            
            // Update ID (Must use Select/Mux)
            bucket.id = miss_logic.select(item, &bucket.id);
        });
    
    profiler.state_update += t2.elapsed();


    // --- STEP 4: FLOOR MAINTENANCE ---
    let t3 = Instant::now();
    
    let any_at_floor = state.buckets.par_iter()
        .map(|bucket| bucket.count.eq(&state.min_val))
        .reduce(|| FheBool::encrypt_trivial(false), |a, b| a | &b);

    let increment = (!any_at_floor).select(one, zero);
    state.min_val = &state.min_val + increment;
    
    profiler.floor_maintenance += t3.elapsed();
    
    // Increment total items processed
    profiler.count += 1;
}

// --- MAIN SIMULATION ---
fn main() {
    // 1. Parse Command Line Arguments
    let args: Vec<String> = env::args().collect();

    // Arg 1: Table Size (Default 10)
    let table_size: usize = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // Arg 2: Stream Size (Default 30)
    let stream_size: usize = args.get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    println!("--- Configuration ---");
    println!("Table Size:  {}", table_size);
    println!("Stream Size: {}", stream_size);
    println!("---------------------");

    println!("Generating keys (this might take a moment)...");
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            // V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
            //     .with_deterministic_execution(),
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            // tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, 
        )
        .build();
    let (client_key, server_key) = generate_keys(config);

    let server_key_clone = server_key.clone();
    
    let worker_pool = rayon::ThreadPoolBuilder::new()
        .start_handler(move |_| {
            set_server_key(server_key_clone.clone());
        })
        .build()
        .unwrap();

    set_server_key(server_key);

    // Generate Stream
    let stream_data: Vec<u32> = (0..stream_size).map(|i| {
        if i % 3 == 0 { 1 } else { (rand::random::<u32>() % 20) + 2 }
    }).collect();

    let mut encrypted_state = EncryptedState {
        buckets: (0..table_size).map(|_| EncryptedBucket {
            id: FheUint32::encrypt(0_u32, &client_key),
            count: FheUint32::encrypt(0_u32, &client_key),
        }).collect(),
        min_val: FheUint32::encrypt(0_u32, &client_key),
        constants: (
            FheUint32::encrypt_trivial(0u32), // Zero
            FheUint32::encrypt_trivial(1u32)  // One
        ),
    };

    println!("Starting FHE processing for {} items...", stream_size);
    let start_time = Instant::now();

    // 3. INIT PROFILER
    let mut profiler = StepProfiler::default();

    let pb = ProgressBar::new(stream_size as u64);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    worker_pool.install(|| {
        for (_idx, &item) in stream_data.iter().enumerate() {
            let enc_item = FheUint32::encrypt(item, &client_key);
            
            process_packet_oblivious(&mut encrypted_state, &enc_item, &mut profiler);
            
            pb.inc(1);
        }
    });
    
    pb.finish_with_message("Done");
    let total_elapsed = start_time.elapsed();

    // 5. PRINT PROFILING RESULTS
    println!("\n{:=^50}", " PERFORMANCE SUMMARY ");
    println!("Total Wall Time:  {:.2?}", total_elapsed);
    println!("Total Items:      {}", profiler.count);
    if profiler.count > 0 {
        println!("Avg Time / Item:  {:.2?}", total_elapsed / profiler.count);
    }
    println!("{}", "-".repeat(50));
    
    // Helper closure to calculate average
    let avg = |dur: Duration| {
        if profiler.count > 0 {
            dur.div_f64(profiler.count as f64)
        } else {
            Duration::ZERO
        }
    };

    println!("{:<25} | {:<15}", "Step", "Avg Time");
    println!("{}", "-".repeat(43));
    println!("{:<25} | {:.2?}", "1. Hit Detection", avg(profiler.hit_detection));
    println!("{:<25} | {:.2?}", "2. Victim Selection", avg(profiler.victim_selection));
    println!("{:<25} | {:.2?}", "3. State Update", avg(profiler.state_update));
    println!("{:<25} | {:.2?}", "4. Floor Maintenance", avg(profiler.floor_maintenance));
    println!("{}", "=".repeat(50));

    // 5. Decrypt and verify
    println!("\n--- Final Encrypted Table Results ---");
    println!("{:<10} | {:<10}", "ID", "Count");
    println!("{}", "-".repeat(25));
    for (_i, bucket) in encrypted_state.buckets.iter().enumerate() {
        let id: u32 = bucket.id.decrypt(&client_key);
        let count: u32 = bucket.count.decrypt(&client_key);
        println!("{:<10} | {:<10}", id, count);
    }

    let final_min: u32 = encrypted_state.min_val.decrypt(&client_key);
    println!("Final Min Floor: {}", final_min);

    let _reference_table = run_plaintext_simulation(&stream_data, table_size); 
}

// Updated to accept dynamic table_size
fn run_plaintext_simulation(stream: &[u32], table_size: usize) -> (Vec<(u32, u32)>, u32) {
    let mut buckets: Vec<(u32, u32)> = vec![(0, 0); table_size];
    let mut min_val = 0;
    for &item in stream {
        let mut hit = false;
        for b in &mut buckets {
            if b.0 == item { b.1 += 1; hit = true; break; }
        }
        if !hit {
            for b in &mut buckets {
                if b.1 == min_val { b.0 = item; b.1 += 1; break; }
            }
        }
        let any_at_floor = buckets.iter().any(|b| b.1 == min_val);
        if !any_at_floor { min_val += 1; }
    }
    
    // --- NEW: Print logic added here ---
    println!("\n--- Reference (Plaintext) Table ---");
    println!("{:<10} | {:<10}", "ID", "Count");
    println!("{}", "-".repeat(25));
    for (id, count) in &buckets {
        println!("{:<10} | {:<10}", id, count);
    }
    println!("Final Floor: {}", min_val);
    println!("-----------------------------------\n");

    (buckets, min_val)
}