use std::str::FromStr;

use super::Cli;
use clap::{Parser, Subcommand};
use smb::*;

#[derive(Parser, Debug)]
pub struct SecurityCmd {
    /// The path of the object to work on
    pub path: UncPath,
    #[command(subcommand)]
    pub subcommand: SecuritySubCommand,
}

#[derive(Subcommand, Debug)]
pub enum SecuritySubCommand {
    /// Displays the security descriptor of a file or directory.
    Get(GetSecurityCmd),
    /// Sets the security descriptor of a file or directory.
    Set(SetSecurityCmd),
}

#[derive(Parser, Debug)]
pub struct GetSecurityCmd {
    #[arg(long)]
    pub dacl: bool,
}

#[derive(Parser, Debug)]
pub struct SetSecurityCmd {
    /// DACLs to add. This is how you can add allow/deny access for users and groups on the object.
    /// Format: (allow|deny):SID:hex-mask
    ///
    /// Example: --add-dacl "allow:S-1-5-21-78297438...:101002ff" - will add the specified SID with the specified mask as an allow ACE.
    #[arg(long, action = clap::ArgAction::Append)]
    pub add_dacl: Vec<DaclEntryArg>,

    /// Remove DACL entries for the specified SIDs.
    ///
    /// Note: this action is applied before any additions via `--add-dacl`.
    #[arg(long, action = clap::ArgAction::Append)]
    pub remove_dacl: Vec<SID>,

    /// Force update ACLs.
    /// * For DACLs, this will overwrite existing DACL entries with same SID.
    #[arg(long, short)]
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct DaclEntryArg {
    pub allow: AceType,
    pub sid: SID,
    pub mask: AccessMask,
}

impl FromStr for DaclEntryArg {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let components = s.split(':').collect::<Vec<_>>();
        if components.len() != 3 {
            return Err(
                "Invalid DACL entry format. Expected format: <allow|deny>:<SID>:<mask>".into(),
            );
        }

        let allow = match components[0].to_lowercase().as_str() {
            "allow" => AceType::AccessAllowed,
            "deny" => AceType::AccessDenied,
            _ => return Err("Invalid ACE type. Expected 'allow' or 'deny'".into()),
        };

        let sid = SID::from_str(components[1]).map_err(|e| format!("Invalid SID: {}", e))?;

        let mask_dword = u32::from_str_radix(components[2].trim_start_matches("0x"), 16)
            .map_err(|e| format!("Invalid mask: {} - requires a 32-bit hexadecimal value (for example: 101002ff)", e))?;
        let mask = AccessMask::from_bytes(mask_dword.to_le_bytes());

        Ok(DaclEntryArg { allow, sid, mask })
    }
}

#[maybe_async::maybe_async]
pub async fn security(
    cmd: &SecurityCmd,
    cli: &Cli,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match &cmd.subcommand {
        SecuritySubCommand::Get(c) => get_security(c, cmd, cli).await,
        SecuritySubCommand::Set(c) => set_security(c, cmd, cli).await,
    }
}

#[maybe_async::maybe_async]
async fn open_resource(
    security_cmd: &SecurityCmd,
    cli: &Cli,
    access: FileAccessMask,
) -> std::result::Result<Resource, Box<dyn std::error::Error>> {
    let client = Client::new(cli.make_smb_client_config()?);

    if security_cmd.path.share().is_none() || security_cmd.path.share().unwrap().is_empty() {
        return Err("Specified path must include a share".into());
    }

    client
        .share_connect(
            &security_cmd.path,
            cli.username.as_ref(),
            cli.password.clone(),
        )
        .await?;
    let resource = client
        .create_file(
            &security_cmd.path,
            &FileCreateArgs::make_open_existing(access),
        )
        .await?;
    Ok(resource)
}

#[inline]
fn resource_handle(resource: &Resource) -> &ResourceHandle {
    match resource {
        Resource::File(f) => f.handle(),
        Resource::Directory(d) => d.handle(),
        Resource::Pipe(p) => p.handle(),
    }
}

#[maybe_async::maybe_async]
pub async fn get_security(
    cmd: &GetSecurityCmd,
    security_cmd: &SecurityCmd,
    cli: &Cli,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let access = FileAccessMask::new().with_read_control(true);
    let resource = open_resource(security_cmd, cli, access).await?;
    let resource_handle = resource_handle(&resource);

    let additional_info = AdditionalInfo::new().with_dacl_security_information(cmd.dacl);
    let security_info = resource_handle.query_security_info(additional_info).await?;

    log::info!("Security info for {}:", security_cmd.path);
    // TODO: pretty print
    log::info!("{:#?}", security_info);

    resource_handle.close().await?;
    Ok(())
}

#[maybe_async::maybe_async]
pub async fn set_security(
    cmd: &SetSecurityCmd,
    security_cmd: &SecurityCmd,
    cli: &Cli,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let write_dacl = !cmd.add_dacl.is_empty() || !cmd.remove_dacl.is_empty();

    let access = FileAccessMask::new()
        .with_read_control(true)
        .with_write_dacl(write_dacl);

    let resource = open_resource(security_cmd, cli, access).await?;
    let resource_handle = resource_handle(&resource);

    // Query only the required information ot perform the update
    let to_set = AdditionalInfo::new().with_dacl_security_information(write_dacl);

    if to_set.into_bytes().iter().all(|f| *f == 0u8) {
        log::debug!("No security information to set.");
        return Ok(());
    }

    let current_security_info = resource_handle.query_security_info(to_set).await?;
    log::debug!("Current security info: {:#?}", current_security_info);

    let mut new_security_info = current_security_info.clone();
    if write_dacl {
        let new_dacl = new_security_info.dacl.as_mut().ok_or_else(|| {
            log::error!("No DACL present on the object, cannot add entries");
            "No DACL present on the object"
        })?;

        // Remove DACLs. Warn if SID not found
        for sid in &cmd.remove_dacl {
            let initial_len = new_dacl.ace.len();
            new_dacl.ace.retain(|ace| match &ace.value {
                AceValue::AccessAllowed(ace) => &ace.sid != sid,
                AceValue::AccessDenied(ace) => &ace.sid != sid,
                _ => true,
            });
            if new_dacl.ace.len() == initial_len {
                log::warn!("No ACE found for SID {}, cannot remove", sid);
            }
            log::debug!(
                "Removed {} DACL entries for SID {}",
                initial_len - new_dacl.ace.len(),
                sid
            );
        }

        // Add DACLs
        for entry in &cmd.add_dacl {
            // Make value
            let access_ace_value_inner = AccessAce {
                access_mask: entry.mask,
                sid: entry.sid.clone(),
            };
            let value = match entry.allow {
                AceType::AccessAllowed => AceValue::AccessAllowed(access_ace_value_inner),
                AceType::AccessDenied => AceValue::AccessDenied(access_ace_value_inner),
                _ => unimplemented!("Unsupported ACE type"),
            };

            // Locate existing entry with same SID
            let existing_ace_to_update = new_dacl.ace.iter_mut().find(|ace| match &ace.value {
                AceValue::AccessAllowed(ace) => ace.sid == entry.sid,
                AceValue::AccessDenied(ace) => ace.sid == entry.sid,
                _ => false,
            });
            if let Some(ace) = existing_ace_to_update {
                if !cmd.force {
                    log::warn!(
                        "ACE for SID {} with mask {:x?} already exists, skipping (use --force to overwrite)",
                        entry.sid,
                        entry.mask
                    );
                    continue;
                }
                log::debug!(
                    "ACE for SID {} already exists, overwriting (mask {:x?})",
                    entry.sid,
                    entry.mask
                );
                // Update
                ace.value = value;
                new_dacl.order_aces();
            } else {
                // Insert
                log::debug!(
                    "Adding ACE for SID {} with mask {:x?}",
                    entry.sid,
                    entry.mask
                );
                new_dacl.insert_ace(ACE {
                    ace_flags: AceFlags::new(),
                    value,
                })
            }
        }
    }

    log::debug!("New security info to set: {:#?}", new_security_info);
    resource_handle
        .set_security_info(new_security_info, to_set)
        .await?;
    resource_handle.close().await?;
    Ok(())
}
