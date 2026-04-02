// Scratch 1
//! Implementation of the netlink transport for receiving raw audit records from
//! the kernel and passing them on through the daemon core.

use anyhow::{Context, Result};

use audit::Handle;
use audit::packet::NetlinkAuditCodec;
use futures::channel::mpsc::UnboundedReceiver;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use audit::{packet::AuditMessage, proto::Connection};
use audit::sys::{SocketAddr, TokioSocket};

use tokio::sync::mpsc::{Sender, Receiver};
use crate::core::netlink::RawAuditRecord;

type KernelConnection = Connection<AuditMessage, TokioSocket, NetlinkAuditCodec>;
type KernelReceiver = UnboundedReceiver<(NetlinkMessage<AuditMessage>, SocketAddr)>; // Should really be exposed in audit crate.
pub type KernelHandle = Handle;


struct NetlinkTransport {}

impl NetlinkTransport {
    /// Creates a connection to the kernel to send and receive Audit related messages.
    /// Will fail if audit::new_connection can't connect.
    fn new() -> Self {
        Self {}
    }

    async fn run(&mut self, output: Sender<RawAuditRecord>) -> Result<()> {
        // Create netlink socket connection
        let (connection, mut handle, mut messages) =
            audit::new_connection().context("Netlink socket connection failed.")?;

        // Spawn connection task
        tokio::spawn(connection);

        // Enable audit events
        handle
            .enable_events()
            .await
            .context("Failed to enable events.")?;

        println!("Netlink audit transport listening for kernel events");

        // Process events from the Linux kernel audit subsystem
        while let Some((msg, _addr)) = messages.next().await {
            if let Some(raw_record) = raw_record_from_netlink_message(&msg) {
                match output.send(raw_record).await {
                    Ok(()) => {},
                    Err(_) => { println!("RawAuditRecord receiver dropped, exiting"); break },
                } 
            }
            else {println!("WARNING! Unknown kernel message received")}
        }
        Ok(())
    }
}

struct NetlinkTransportHandle {
    // Contains handles for shutdown and communication.
}
impl NetlinkTransportHandle {
    fn new() -> Self {
        Self {}
    }
}

fn raw_record_from_netlink_message(msg: &NetlinkMessage<audit::packet::AuditMessage>)
-> Option<RawAuditRecord> {
    if let NetlinkPayload::InnerMessage(inner) = &msg.payload {
        let data = match inner {
            AuditMessage::Event((_, kvs)) => kvs.to_string(),
            AuditMessage::Other((_, data)) => data.clone(),
            _ => return None,
        };

        let record_id = msg.header.message_type;
        Some(RawAuditRecord::new(record_id, data))
    } else {
        None
    }
}