mod config;
mod logger;
mod types;
mod worker;
mod aggregator;

use config::load_config;
use logger::init_logger;
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheUint32};
use rand::prelude::*;
use rand_distr::{Zipf, Distribution};
use crossbeam_channel::bounded;
use std::thread;
use std::time::Instant;
use log::info;
use indicatif::{ProgressBar, ProgressStyle}; // <-- New import

fn generate_zipf_stream(len: usize, max_val: u64, exponent: f64) -> Vec<u32> {
    let mut rng = thread_rng();
    let zipf = Zipf::new(max_val, exponent).unwrap();
    (0..len).map(|_| zipf.sample(&mut rng) as u32 + 1).collect()
}

fn main() {
    init_logger();
    let config = load_config();
    info!("Starting Distributed FHE Stream Processor");

    info!("Generating TFHE keys...");
    let tfhe_config = ConfigBuilder::default()
        .use_custom_parameters(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS)
        .build();
    let (client_key, server_key) = generate_keys(tfhe_config);

    let stream = generate_zipf_stream(config.simulation.stream_size, 50, config.simulation.zipf_exponent);

    let (stream_tx, stream_rx) = bounded(config.system.channel_buffer_size);
    let (flush_tx, flush_rx) = bounded(config.system.channel_buffer_size);

    let sk_agg = server_key.clone();
    let cfg_agg = config.clone();
    let aggregator_handle = thread::spawn(move || {
        aggregator::spawn_aggregator(cfg_agg, sk_agg, flush_rx)
    });

    // --- SETUP PROGRESS BAR ---
    let pb = ProgressBar::new(config.simulation.stream_size as u64);
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) ETA: {eta}"
    ).unwrap().progress_chars("#>-"));
    // --------------------------

    let mut worker_handles = vec![];
    for w_id in 0..config.system.num_workers {
        let rx = stream_rx.clone();
        let tx = flush_tx.clone();
        let sk = server_key.clone();
        let cfg = config.clone();
        let pb_clone = pb.clone(); // <-- Clone the progress bar for this worker
        
        let handle = thread::spawn(move || {
            // Pass the progress bar into the worker
            worker::spawn_worker(w_id, cfg, sk, rx, tx, pb_clone); 
        });
        worker_handles.push(handle);
    }

    drop(flush_tx); 

    info!("Dispatching stream items...");
    let start_time = Instant::now();
    
    for &item in &stream {
        let enc_item = FheUint32::encrypt(item, &client_key);
        stream_tx.send(enc_item).unwrap();
    }
    
    drop(stream_tx);
    info!("Stream fully dispatched. Waiting for workers to finish...");

    for handle in worker_handles {
        handle.join().unwrap();
    }
    
    // Stop the progress bar visually
    pb.finish_with_message("Workers Complete");
    
    let final_state = aggregator_handle.join().unwrap();
    let total_time = start_time.elapsed();

    info!("Pipeline complete in {:.2?}. Decrypting results...", total_time);
    
    println!("\n{:=^40}", " FINAL RESULTS ");
    for bucket in final_state.buckets {
        let id: u32 = bucket.id.decrypt(&client_key);
        let count: u16 = bucket.count.decrypt(&client_key);
        if id != 0 {
            println!("ID: {:<5} | Count: {}", id, count);
        }
    }
}