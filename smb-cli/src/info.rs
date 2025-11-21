use crate::Cli;
use clap::{Parser, ValueEnum};
#[cfg(feature = "async")]
use futures_util::StreamExt;
use maybe_async::*;
use smb::{Client, FileAccessMask, FileBasicInformation, QueryQuotaInfo, UncPath, resource::*};
use std::collections::VecDeque;
use std::fmt::Display;
use std::{error::Error, sync::Arc};

type DirectoryInfoQueryType = smb::FileIdBothDirectoryInformation;

/// Recursion mode options
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecursiveMode {
    /// Do not recurse into subdirectories
    #[default]
    NonRecursive,
    /// List all files and directories
    List,
}

impl Display for RecursiveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecursiveMode::NonRecursive => write!(f, "non-recursive"),
            RecursiveMode::List => write!(f, "list"),
        }
    }
}

#[derive(Parser, Debug)]
pub struct InfoCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: UncPath,

    /// Mode of recursion for directory listings
    #[arg(short, long)]
    #[clap(default_value_t = RecursiveMode::NonRecursive)]
    pub recursive: RecursiveMode,

    /// Whether to display quota information on the directory being queried.
    #[arg(long)]
    #[clap(default_value_t = false)]
    pub show_quota: bool,

    /// Whether to display extended attributes (EA) information for files.
    #[arg(long)]
    #[clap(default_value_t = false)]
    pub show_ea: bool,
}

#[maybe_async]
pub async fn info(cmd: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let client = Client::new(cli.make_smb_client_config()?);

    if cmd.path.share().is_none() || cmd.path.share().unwrap().is_empty() {
        client
            .ipc_connect(cmd.path.server(), &cli.username, cli.password.clone())
            .await?;
        let shares_info = client.list_shares(cmd.path.server()).await?;
        log::info!("Available shares on {}: ", cmd.path.server());
        for share in shares_info {
            log::info!("  - {}", **share.netname.as_ref().unwrap());
        }
        return Ok(());
    }

    client
        .share_connect(&cmd.path, cli.username.as_ref(), cli.password.clone())
        .await?;
    let resource = client
        .create_file(
            &cmd.path,
            &FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true)),
        )
        .await?;

    match resource {
        Resource::File(file) => {
            let info: FileBasicInformation = file.query_info().await?;
            let size_kb = file.get_len().await?.div_ceil(1024);
            log::info!("{}", cmd.path);
            log::info!("  - Size: ~{size_kb}kB");
            log::info!("  - Creation time: {}", info.creation_time);
            log::info!("  - Last write time: {}", info.last_write_time);
            log::info!("  - Last access time: {}", info.last_access_time);
            if cmd.show_ea {
                log::info!("  - Extended Attributes (EA):");
                let basic_ea_info = file.query_info::<smb::FileEaInformation>().await?;
                if basic_ea_info.ea_size > 0 {
                    let ea_info = file
                        .query_full_ea_info_with_options(
                            vec![],
                            Some(basic_ea_info.ea_size as usize),
                        )
                        .await?;
                    ea_info.iter().for_each(|ea| {
                        log::info!(
                            "       - name='{}', size={} bytes, flags={:?}",
                            ea.ea_name,
                            ea.ea_value.len(),
                            ea.flags
                        );
                    });
                } else {
                    log::info!("       (no EAs present)");
                }
            }
            file.close().await?;
        }
        Resource::Directory(dir) => {
            let dir = Arc::new(dir);
            if cmd.show_quota {
                try_query_and_show_quota(&dir).await;
            }
            iterate_directory(
                &dir,
                &cmd.path,
                "*",
                &IterateParams {
                    client: &client,
                    recursive: cmd.recursive,
                    show_quota: cmd.show_quota,
                },
            )
            .await?;
            dir.close().await?;
        }
        Resource::Pipe(p) => {
            log::info!("Pipe");
            p.close().await?;
        }
    };

    client.close().await?;

    Ok(())
}

fn display_item_info(info: &DirectoryInfoQueryType, dir_path: &UncPath) {
    if info.file_name == "." || info.file_name == ".." {
        return; // Skip current and parent directory entries
    }

    match info.file_attributes.directory() {
        true => log::info!("  - {} {dir_path}/{}/", "(D)", info.file_name),
        false => log::info!(
            "  - {} {dir_path}/{} ~{}",
            "(F)",
            info.file_name,
            get_size_string(info.end_of_file)
        ),
    }
}

fn display_quota_info(info: &Vec<smb::FileQuotaInformation>) {
    for quota in info {
        if quota.quota_limit == u64::MAX && quota.quota_threshold == u64::MAX {
            log::trace!("Skipping quota for SID {} with no limit", quota.sid);
            continue; // No quota set
        }
        log::info!(
            "Quota for SID {}: used {}, threshold {}, limit {}",
            quota.sid,
            get_size_string(quota.quota_used),
            get_size_string(quota.quota_threshold),
            get_size_string(quota.quota_limit)
        );
    }
}

fn get_size_string(size_bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    match size_bytes {
        x if x == u64::MAX => "∞".to_string(),
        x if x >= GB => format!("{:.2} GB", x as f64 / GB as f64),
        x if x >= MB => format!("{:.2} MB", x as f64 / MB as f64),
        x if x >= KB => format!("{:.2} kB", x as f64 / KB as f64),
        x => format!("{} B", x),
    }
}

struct IterateParams<'a> {
    client: &'a Client,
    recursive: RecursiveMode,
    show_quota: bool,
}
struct IteratedItem {
    dir: Arc<Directory>,
    path: UncPath,
}

#[maybe_async]
async fn iterate_directory(
    dir: &Arc<Directory>,
    dir_path: &UncPath,
    pattern: &str,
    params: &IterateParams<'_>,
) -> smb::Result<()> {
    let mut subdirs = VecDeque::new();
    subdirs.push_back(IteratedItem {
        dir: Arc::clone(dir),
        path: dir_path.clone(),
    });

    while subdirs.front().is_some() {
        iterate_dir_items(&subdirs.pop_front().unwrap(), pattern, &mut subdirs, params).await?;

        assert!(params.recursive >= RecursiveMode::List || subdirs.is_empty())
    }
    Ok(())
}

#[async_impl]
async fn iterate_dir_items(
    item: &IteratedItem,
    pattern: &str,
    subdirs: &mut VecDeque<IteratedItem>,
    params: &IterateParams<'_>,
) -> smb::Result<()> {
    let mut info_stream = Directory::query::<DirectoryInfoQueryType>(&item.dir, pattern).await?;
    while let Some(info) = info_stream.next().await {
        if let Some(to_push) = handle_iteration_item(&info?, &item.path, params).await {
            subdirs.push_back(to_push);
        }
    }
    Ok(())
}

#[sync_impl]
fn iterate_dir_items(
    item: &IteratedItem,
    pattern: &str,
    subdirs: &mut VecDeque<IteratedItem>,
    params: &IterateParams<'_>,
) -> smb::Result<()> {
    for info in Directory::query::<DirectoryInfoQueryType>(&item.dir, pattern)? {
        if let Some(to_push) = handle_iteration_item(&info?, &item.path, params) {
            subdirs.push_back(to_push);
        }
    }
    Ok(())
}

#[maybe_async]
async fn handle_iteration_item(
    info: &DirectoryInfoQueryType,
    dir_path: &UncPath,
    params: &IterateParams<'_>,
) -> Option<IteratedItem> {
    display_item_info(info, dir_path);

    if params.recursive < RecursiveMode::List && !params.show_quota {
        return None;
    }

    if !info.file_attributes.directory() || info.file_name == "." || info.file_name == ".." {
        return None;
    }

    let path_of_subdir = dir_path.clone().with_add_path(&info.file_name.to_string());
    let dir_result = params
        .client
        .create_file(
            &path_of_subdir,
            &FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true)),
        )
        .await;

    if let Err(e) = dir_result {
        log::warn!("Failed to open directory {}: {}", path_of_subdir, e);
        return None;
    }

    let dir = dir_result.unwrap();

    let dir: Directory = match dir.try_into() {
        Ok(dir) => dir,
        Err(e) => {
            log::warn!(
                "Failed to convert resource to directory {}: {}",
                path_of_subdir,
                e.0
            );
            return None;
        }
    };

    // Quota information
    if params.show_quota {
        try_query_and_show_quota(&dir).await;
    }

    // Recursion
    if params.recursive >= RecursiveMode::List {
        Some(IteratedItem {
            dir: Arc::new(dir),
            path: path_of_subdir,
        })
    } else {
        dir.close().await.ok()?;
        None
    }
}

#[maybe_async]
async fn try_query_and_show_quota(dir: &Directory) {
    match dir
        .query_quota_info(QueryQuotaInfo::new(false, true, vec![]))
        .await
    {
        Ok(qi) => display_quota_info(&qi),
        Err(e) => log::warn!("Failed to query quota info: {}", e),
    }
}
