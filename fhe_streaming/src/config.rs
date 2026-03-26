use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct SystemConfig {
    pub num_workers: usize,
    pub worker_threads: usize,
    pub aggregator_threads: usize,
    pub channel_buffer_size: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AlgorithmConfig {
    pub table_size_k: usize,
    pub flush_threshold: u32,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SimulationConfig {
    pub stream_size: usize,
    pub zipf_exponent: f64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub system: SystemConfig,
    pub algorithm: AlgorithmConfig,
    pub simulation: SimulationConfig,
}

pub fn load_config() -> AppConfig {
    let config_str = fs::read_to_string("config.toml")
        .expect("Failed to read config.toml");
    toml::from_str(&config_str).expect("Failed to parse config.toml")
}