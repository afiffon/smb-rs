use crate::Cli;
use clap::Parser;
use maybe_async::*;
use smb::{Client, DirAccessMask, NotifyFilter, UncPath, resource::*, sync_helpers::*};
use std::error::Error;

#[derive(Parser, Debug)]
pub struct WatchCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: UncPath,

    /// Whether to watch recursively in all subdirectories.
    #[arg(short, long, default_value_t = false)]
    pub recursive: bool,

    /// The number of changes to watch for before exiting. If not specified, will watch indefinitely.
    #[arg(short)]
    pub number: Option<usize>,
}

#[maybe_async]
pub async fn watch(cmd: &WatchCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if cmd.path.share().is_none() || cmd.path.share().unwrap().is_empty() {
        return Err("Path must include a share name".into());
    }

    let client = Client::new(cli.make_smb_client_config()?);
    client
        .share_connect(&cmd.path, &cli.username, cli.password.clone())
        .await?;

    let dir_resource = client
        .create_file(
            &cmd.path,
            &FileCreateArgs::make_open_existing(
                DirAccessMask::new().with_list_directory(true).into(),
            ),
        )
        .await?;

    let dir: Directory = dir_resource
        .try_into()
        .map_err(|_| "The specified path is not a directory")?;
    let dir = Arc::new(dir);

    log::info!("Watching directory: {}", cmd.path);
    watch_dir(
        &dir,
        NotifyFilter::all(),
        cmd.recursive,
        cmd.number.unwrap_or(usize::MAX),
    )
    .await?;

    dir.close().await?;
    client.close().await?;
    Ok(())
}

#[cfg(feature = "async")]
async fn watch_dir(
    dir: &Arc<Directory>,
    notify_filter: NotifyFilter,
    recursive: bool,
    number: usize,
) -> Result<(), Box<dyn Error>> {
    use futures::StreamExt;

    let cancellation = CancellationToken::new();
    ctrlc::set_handler({
        let cancellation = cancellation.clone();
        move || {
            log::info!("Cancellation requested, stopping watch...");
            cancellation.cancel();
        }
    })?;

    Directory::watch_stream_cancellable(dir, notify_filter, recursive, cancellation)?
        .take(number)
        .for_each(|res| {
            match res {
                Ok(info) => {
                    log::info!("Change detected: {:?}", info);
                }
                Err(e) => {
                    log::error!("Error watching directory: {}", e);
                }
            }
            futures::future::ready(())
        })
        .await;

    Ok(())
}

#[cfg(feature = "multi_threaded")]
fn watch_dir(
    dir: &Arc<Directory>,
    notify_filter: NotifyFilter,
    recursive: bool,
    number: usize,
) -> Result<(), Box<dyn Error>> {
    let iterator = Directory::watch_stream(dir, notify_filter, recursive)?;
    let canceller = iterator.get_canceller();

    ctrlc::set_handler({
        let canceller = canceller.clone();
        move || {
            log::info!("Cancellation requested, stopping watch...");
            canceller.cancel();
        }
    })?;

    for res in iterator.take(number) {
        match res {
            Ok(info) => {
                log::info!("Change detected: {:?}", info);
            }
            Err(e) => {
                log::error!("Error watching directory: {}", e);
            }
        }
    }

    Ok(())
}

#[cfg(feature = "single_threaded")]
fn watch_dir(
    dir: &Arc<Directory>,
    notify_filter: NotifyFilter,
    recursive: bool,
    number: usize,
) -> Result<(), Box<dyn Error>> {
    log::warn!("Single-threaded mode does not support clean cancellation. Press Ctrl+C to exit.");

    for res in Directory::watch_stream(dir, notify_filter, recursive)?.take(number) {
        match res {
            Ok(info) => {
                log::info!("Change detected: {:?}", info);
            }
            Err(e) => {
                log::error!("Error watching directory: {}", e);
            }
        }
    }

    Ok(())
}
