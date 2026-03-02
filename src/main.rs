#![allow(warnings)]
use std::sync::Arc;
use std::time::Duration; // todo - when to use std::sync vs tokio::sync ?? tokio docs say something about access across threads
use tokio::signal;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use clap::Parser;

use auditrs::cli::{Cli, Commands};
use auditrs::{
    correlator::{AuditEvent, Correlator},
    netlink::{NetlinkAuditTransport, RawAuditRecord},
    parser::ParsedAuditRecord,
    daemon
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if(std::env::consts::OS != "linux") {
        println!("auditRS is only supported on Linux");
        return Ok(());
    }

    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Start => start_auditrs().await,
        Commands::Stop => stop_auditrs(),
        Commands::Dump => dump_auditrs(),
        Commands::Status => status_auditrs(),
        Commands::Config => config_auditrs(),
    };

    /// Im not sure why this prints with quotes
    /// anyways I think we should add a verbose flag for more detailed error messages
    if let Err(e) = result {
        return Err(e);
    }

    Ok(())
}

async fn start_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting auditRS");
    daemon::start_daemon()?;

    run_worker().await
}

async fn run_worker() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize components.
    let transport = NetlinkAuditTransport::new();
    let raw_audit_rx = transport.into_receiver();
    let correlator = Arc::new(Mutex::new(Correlator::new()));

    let (parsed_audit_tx, parsed_audit_rx) = mpsc::channel(1000);
    let (correlated_event_tx, correlated_event_rx) = mpsc::channel(1000);

    let parser_task = spawn_parser_task(raw_audit_rx, parsed_audit_tx);
    let correlator_task = spawn_correlator_task(correlator, parsed_audit_rx, correlated_event_tx);
    let temp_output_task = tokio::spawn(async move {
        let mut rx = correlated_event_rx;
        while rx.recv().await.is_some() {}
    });

    // to be removed
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = signal::ctrl_c() => {} 
            _ = sigterm.recv() => {}
        }
    }

    parser_task.abort();
    correlator_task.abort();
    temp_output_task.abort();
    let _ = tokio::join!(parser_task, correlator_task, temp_output_task);

    daemon::remove_pid_file();

    Ok(())
}

fn stop_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    {
        daemon::stop_daemon()?;
        println!("Stopped auditRS daemon");
    }
    Ok(())
}

fn dump_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!("Dump, WIP");
    Ok(())
}

fn status_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!("auditRS is {}", if daemon::is_running() { "running" } else { "not running" });
    Ok(())
}

fn config_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!("Config, WIP");
    Ok(())
}

fn spawn_parser_task(
    mut receiver: mpsc::Receiver<RawAuditRecord>,
    sender: mpsc::Sender<ParsedAuditRecord>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(raw_record) = receiver.recv().await {
            let parsed_record = ParsedAuditRecord::try_from(raw_record).unwrap();
            println!("Parsed record: {:?}", parsed_record);
            sender.send(parsed_record).await.unwrap();
        }
    })
}

fn spawn_correlator_task(
    correlator: Arc<Mutex<Correlator>>,
    mut receiver: mpsc::Receiver<ParsedAuditRecord>,
    sender: mpsc::Sender<AuditEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            /// Two async branches are run, the first to succeed will be executed.
            /// The second branch is executed periodically, every 500ms.
            tokio::select! {
                Some(record) = receiver.recv() => {
                    correlator.lock().await.push(record);
                }
                _ = sleep(Duration::from_millis(500)) => {
                    let mut corr = correlator.lock().await;
                    for event in corr.flush_expired() {
                        println!("Correlated event: {:?}", event);
                        sender.send(event).await.unwrap();
                    }
                }
            }
        }
    })
}

fn spawn_writer_task(
    _writer: Arc<Mutex<auditrs::writer::AuditLogWriter>>,
    mut _receiver: mpsc::Receiver<AuditEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            println!("writng the disk :p");
            sleep(Duration::from_millis(100)).await;
            /* e.g.,
            let event = receiver.recv().await
            write_event_to_disk(event);
            */
        }
    })
}