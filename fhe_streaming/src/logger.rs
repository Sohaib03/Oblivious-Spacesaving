use std::fs;
use chrono::Local;

pub fn init_logger() {
    // Ensure logs directory exists
    fs::create_dir_all("logs").unwrap();

    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let log_file = format!("logs/run_{}.log", timestamp);

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        // .chain(std::io::stdout()) // Print to console
        .chain(fern::log_file(log_file).unwrap()) // Save to file
        .apply()
        .unwrap();
}