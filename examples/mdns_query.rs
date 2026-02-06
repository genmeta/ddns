use std::{io::Error, net::IpAddr};

use clap::Parser;

const SERVICE_NAME: &str = "_genmeta.local";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    ip: IpAddr,
    #[arg(long, default_value = "lo0")]
    device: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mdns = gmdns::mdns::Mdns::new(SERVICE_NAME, args.ip, &args.device)?;

    let ret = mdns.query("mdns.test.genmeta.net").await?;
    println!("{ret:?}\n");
    Ok(())
}
