# SMB Messages

This crate contains SMB-specific messages and structures,
that are used by the SMB protocol.

Mostly, it contains SMB messages (like SMB2 Headers, SMB2 Requests & Responses, etc.).
It also contains additional structures that are used by SMB specifically
(for example, DFS referrals), but common structures (such as GUID) are found in the `smb-types` crate.

> This crate is a part of the `smb-rs` project

## Usage

This crate is meant to be used with anyone who wants to implement SMB-related functionality in Rust.
See the documentation of the crate for more information.

Configure the features to your use case: use `server`, `client`, or `both`.

## Documentation Note

Documentation for most of the structures in this crate is based on the official Microsoft documentation,
and is vibe-documented accordingly (you can see the instructions in `.github/copilot-instructions.md` :)).

My tip for those who want an advanced, in-depth understanding of the SMB2 protocol - open up the official MS-SMB2 documentation from Microsoft,
and read it alongside the code and documentation here.
Most structs are named properly and are easily mappable to the official documentation, so you can get a deep understanding of the protocol that way.

## Code Generation

See the `smb-dtyp-derive` crate for more information about the code generation proc-macros used in this crate.
