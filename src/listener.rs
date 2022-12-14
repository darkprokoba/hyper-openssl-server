// Copyright 2022 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause

use openssl::ssl::{Ssl, SslAcceptor, SslContext};
use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Sender};
use tokio::task::JoinHandle;
use tokio_openssl::SslStream;
use tokio_stream::wrappers::ReceiverStream;

type ConnStream = ReceiverStream<Result<SslStream<TcpStream>, std::io::Error>>;

pub async fn init(
    listen_addr: &str,
    num_acceptor_tasks: usize,
    acceptor: SslAcceptor,
) -> Result<(ConnStream, Vec<JoinHandle<()>>), Box<dyn Error>> {
    let (tx, rx) = channel::<Result<SslStream<TcpStream>, std::io::Error>>(10);

    let tcp_listener = TcpListener::bind(listen_addr).await?;
    let tcp_listener = Arc::new(tcp_listener);
    let mut acceptor_tasks = Vec::new();
    let ssl_ctx = acceptor.into_context();
    for _i in 0..num_acceptor_tasks {
        let tx = tx.clone();
        let listener = tcp_listener.clone();
        let join = tokio::spawn(accept(listener, ssl_ctx.clone(), tx));
        acceptor_tasks.push(join);
    }

    let conn_stream = ReceiverStream::new(rx);
    Ok((conn_stream, acceptor_tasks))
}

pub async fn join(tasks: Vec<JoinHandle<()>>) -> Result<(), Box<dyn Error>> {
    for join in tasks.into_iter() {
        join.await?;
    }

    Ok(())
}

async fn accept(
    listener: Arc<TcpListener>,
    acceptor: SslContext,
    tx: Sender<Result<SslStream<TcpStream>, std::io::Error>>,
) {
    loop {
        let sent = accept_impl(listener.clone(), &acceptor, &tx).await;
        match sent {
            Ok(result) => {
                if !result {
                    tracing::info!("Acceptor graceful shutdown!");
                    return;
                }
            }
            Err(err) => tracing::error!("Could not handle incoming request: {}", err),
        }
    }
}

async fn accept_impl(
    listener: Arc<TcpListener>,
    acceptor: &SslContext,
    tx: &Sender<Result<SslStream<TcpStream>, std::io::Error>>,
) -> Result<bool, Box<dyn Error>> {
    // wait (with a timeout) for a new incoming tcp connection:
    let tcp_accept = tokio::time::timeout(Duration::from_secs(30), listener.accept()).await;
    if tcp_accept.is_err() {
        // a timeout occurred, check if the hyper server went away:
        return Ok(!tx.is_closed());
    }

    let (tcp_stream, _addr) = tcp_accept.expect("Unreachable")?;
    let ssl = Ssl::new(acceptor)?;
    let mut ssl_stream = SslStream::new(ssl, tcp_stream)?;
    Pin::new(&mut ssl_stream).accept().await?;

    Ok(tx.send(Ok(ssl_stream)).await.is_ok())
}
