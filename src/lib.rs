// Copyright 2022 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause

mod listener;

pub use listener::*;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::server::accept;
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslOptions};
    use reqwest::StatusCode;
    use std::convert::Infallible;
    use std::error::Error;
    use std::sync::Arc;
    use test_log::test;
    use tokio::sync::broadcast::{channel, Sender};
    use warp::Filter;

    pub const KEY_FILE: &str = "./test/key.pem";
    pub const CERT_FILE: &str = "./test/cert.pem";

    fn openssl_acceptor() -> Result<SslAcceptor, Box<dyn Error>> {
        let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls())?;

        acceptor.set_private_key_file(KEY_FILE, SslFiletype::PEM)?;
        acceptor.set_certificate_chain_file(CERT_FILE)?;

        acceptor.set_cipher_list(
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
             ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:\
             ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        )?;

        acceptor.clear_options(SslOptions::NO_TLSV1_3);

        Ok(acceptor.build())
    }

    #[test(tokio::test)]
    async fn warp_openssl() -> Result<(), Box<dyn Error>> {

        tracing::info!("Bringing up a warp openssl endpoint...");

        let (conn_stream, _acceptor_tasks) = init("[::]:3030", 16, openssl_acceptor()?).await?;

        // Warp setup:
        let (sig_quit_tx, mut sig_quit_rx) = channel::<()>(1);
        let sig_quit_tx = Arc::new(sig_quit_tx);
        let with_state = warp::any().map(move || sig_quit_tx.clone());

        let hello = warp::path!("hello").map(|| "Hello, world!"); // this one always succeeds, even over a network
        let test = warp::path("ui").and(warp::fs::file("./two.js"));
        let graceful_quit = warp::path!("quit")
            .and(with_state)
            .map(|sig: Arc<Sender<()>>| {
                let res = sig.send(());
                if res.is_err() {
                    "Could not send quit message!"
                } else {
                    "graceful shutdown!"
                }
            });

        // Convert it into a `Service`...
        let svc = warp::service(hello.or(test).or(graceful_quit));

        let make_svc = hyper::service::make_service_fn(move |_| {
            let svc = svc.clone();
            async move { Ok::<_, Infallible>(svc) }
        });

        let server = hyper::Server::builder(accept::from_stream(conn_stream))
            .serve(make_svc)
            .with_graceful_shutdown(async move {
                sig_quit_rx.recv().await.ok();
            });

        let server_handle = tokio::spawn(server);

        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()?;
        let response = client
            .get("https://localhost:3030/hello")
            .send()
            .await?
            .text()
            .await?;
        assert_eq!("Hello, world!", response);

        let response_code = client
            .get("https://localhost:3030/quit")
            .send()
            .await?
            .status();
        assert_eq!(StatusCode::OK, response_code);

        server_handle.await??;

        Ok(())
    }
}
