use crate::{Cli, path::*};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use maybe_async::*;
use smb::sync_helpers::*;
use smb::{Client, CreateOptions, FileAccessMask, FileAttributes, resource::*};
use std::collections::HashMap;
use std::error::Error;
#[cfg(not(feature = "async"))]
use std::fs;
#[cfg(not(feature = "single_threaded"))]
use std::sync::Arc;
#[cfg(feature = "multi_threaded")]
use std::thread::sleep;

#[cfg(feature = "async")]
use tokio::{fs, time::sleep};

#[derive(Parser, Debug)]
pub struct CopyCmd {
    /// Force copy, overwriting existing file(s).
    #[arg(short, long)]
    pub force: bool,

    /// Source path
    pub from: Path,
    /// Destination path
    pub to: Path,
}

enum CopyFileValue {
    Local(Mutex<fs::File>),
    Remote(File),
}

struct CopyFile {
    path: Path,
    value: CopyFileValue,
}

impl CopyFile {
    #[maybe_async]
    async fn open(
        path: &Path,
        client: &Client,
        cli: &Cli,
        cmd: &CopyCmd,
        read: bool,
    ) -> Result<Self, smb::Error> {
        let value = match path {
            Path::Local(path_buf) => {
                let file = fs::OpenOptions::new()
                    .read(read)
                    .write(!read)
                    .create(!read)
                    .create_new(!read && !cmd.force)
                    .truncate(!read)
                    .open(path_buf)
                    .await?;
                CopyFileValue::Local(Mutex::new(file))
            }
            Path::Remote(unc_path) => {
                client
                    .share_connect(unc_path, cli.username.as_str(), cli.password.clone())
                    .await?;
                let create_args = if read {
                    FileCreateArgs::make_open_existing(
                        FileAccessMask::new().with_generic_read(true),
                    )
                } else if cmd.force {
                    FileCreateArgs::make_overwrite(
                        FileAttributes::new().with_archive(true),
                        CreateOptions::new(),
                    )
                } else {
                    FileCreateArgs::make_create_new(
                        FileAttributes::new().with_archive(true),
                        CreateOptions::new(),
                    )
                };
                let file = client
                    .create_file(unc_path, &create_args)
                    .await?
                    .unwrap_file();
                CopyFileValue::Remote(file)
            }
        };
        Ok(CopyFile {
            path: path.clone(),
            value,
        })
    }

    #[cfg(not(feature = "single_threaded"))]
    #[maybe_async]
    async fn _get_channel_to_jobs_map(
        &self,
        to: &CopyFile,
        client: &Client,
    ) -> smb::Result<HashMap<Option<u32>, usize>> {
        use Path::*;

        const R2R_WORKERS_NO_MC: usize = 8;
        match (&self.path, &to.path) {
            (Remote(_), Remote(_)) => return Ok(HashMap::from([(None, R2R_WORKERS_NO_MC)])),
            (Local(_), Local(_)) => unreachable!(),
            _ => (),
        }

        // Remote to/from local file copy
        // Initialize multi-channel if possible
        const R2L_L2R_WORKERS_NO_MC: usize = 16;
        if !client.config().connection.multichannel.is_enabled() {
            return Ok(HashMap::from([(None, R2L_L2R_WORKERS_NO_MC)]));
        }

        let remote_address = match &self.path {
            Remote(p) => p,
            Local(_) => match &to.path {
                Remote(p) => p,
                Local(_) => unreachable!(),
            },
        };

        let channels = client.get_channels(remote_address).await?;

        const L2R_R2L_PER_CHANNEL_WORKERS: usize = 16;
        let channels = channels
            .iter()
            .map(|(&channel_id, _)| (Some(channel_id), L2R_R2L_PER_CHANNEL_WORKERS))
            .collect::<HashMap<Option<u32>, usize>>();

        log::debug!("Using {} channels for copy", channels.len());
        log::trace!("Channel to jobs map: {channels:?}");

        Ok(channels)
    }

    #[cfg(feature = "single_threaded")]
    fn _get_channel_to_jobs_map(
        &self,
        _to: &CopyFile,
        _client: &Client,
    ) -> smb::Result<HashMap<Option<u32>, usize>> {
        // Well, it's ignored anyway. We keep it just to be consistent.
        Ok(HashMap::from([(None, 1)]))
    }

    #[maybe_async]
    async fn copy_to(self, to: CopyFile, client: &Client) -> Result<(), smb::Error> {
        use CopyFileValue::*;

        let channel_jobs = self._get_channel_to_jobs_map(&to, client).await?;

        match self.value {
            Local(from_local) => match to.value {
                Local(_) => unreachable!(),
                Remote(to_remote) => Self::do_copy(from_local, to_remote, channel_jobs).await?,
            },
            Remote(from_remote) => match to.value {
                Local(to_local) => Self::do_copy(from_remote, to_local, channel_jobs).await?,
                Remote(to_remote) => {
                    if to.path.as_remote().unwrap().server()
                        == self.path.as_remote().unwrap().server()
                        && to.path.as_remote().unwrap().share()
                            == self.path.as_remote().unwrap().share()
                    {
                        // Use server-side copy if both files are on the same server
                        to_remote.srv_copy(&from_remote).await?
                    } else {
                        Self::do_copy(from_remote, to_remote, channel_jobs).await?
                    }
                }
            },
        }
        Ok(())
    }

    #[maybe_async]
    #[cfg(not(feature = "single_threaded"))]
    pub async fn do_copy<
        F: ReadAtChannel + GetLen + Send + Sync + 'static,
        T: WriteAtChannel + SetLen + Send + Sync + 'static,
    >(
        from: F,
        to: T,
        channel_jobs: HashMap<Option<u32>, usize>,
    ) -> smb::Result<()> {
        let state = prepare_parallel_copy(&from, &to, channel_jobs).await?;
        let state = Arc::new(state);
        let progress_handle = Self::progress(state.clone());
        start_parallel_copy(from, to, state).await?;

        #[cfg(feature = "async")]
        progress_handle.await.unwrap();
        #[cfg(not(feature = "async"))]
        progress_handle.join().unwrap();
        Ok(())
    }

    /// Single-threaded copy implementation.
    #[cfg(feature = "single_threaded")]
    pub fn do_copy<F: ReadAtChannel + GetLen, T: WriteAtChannel + SetLen>(
        from: F,
        to: T,
        _channels: HashMap<Option<u32>, usize>,
    ) -> smb::Result<()> {
        let progress = Self::make_progress_bar(from.get_len()?);
        block_copy_progress(
            from,
            to,
            Some(&move |current| {
                progress.set_position(current);
            }),
        )
    }

    /// Async progress bar task starter.
    #[cfg(feature = "async")]
    fn progress(state: Arc<CopyState>) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move { Self::progress_loop(state).await })
    }

    /// Thread progress bar task starter.
    #[cfg(feature = "multi_threaded")]
    fn progress(state: Arc<CopyState>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            Self::progress_loop(state);
        })
    }

    /// Thread/task entrypoint for measuring and displaying copy progress.
    #[cfg(not(feature = "single_threaded"))]
    #[maybe_async]
    async fn progress_loop(state: Arc<CopyState>) {
        let progress_bar = Self::make_progress_bar(state.total_size());
        loop {
            let bytes_copied = state.bytes_copied();
            progress_bar.set_position(bytes_copied);
            if bytes_copied >= state.total_size() {
                break;
            }
            sleep(std::time::Duration::from_millis(100)).await;
        }
        progress_bar.finish_with_message("Copy complete");
    }

    /// Returns a new progress bar instance for copying files.
    fn make_progress_bar(len: u64) -> ProgressBar {
        let progress = ProgressBar::new(len);
        progress.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                    .unwrap().progress_chars("#>-"));
        progress
    }
}

#[maybe_async]
pub async fn copy(cmd: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if matches!(cmd.from, Path::Local(_)) && matches!(cmd.to, Path::Local(_)) {
        return Err("Copying between two local files is not supported. Use `cp` or `copy` shell commands instead :)".into());
    }

    let client = Client::new(cli.make_smb_client_config()?);
    let from = CopyFile::open(&cmd.from, &client, cli, cmd, true).await?;
    let to = CopyFile::open(&cmd.to, &client, cli, cmd, false).await?;

    let copy_ok = from.copy_to(to, &client).await;

    client.close().await?;

    Ok(copy_ok?)
}
