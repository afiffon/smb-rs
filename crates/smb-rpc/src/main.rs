/* TEMP - SHOULD NOT BE IN MASTER!!! */

use smb_rpc::idl::syntax::*;
use smb_rpc::*;

use pest::Parser;

fn main() {
    println!("SMB RPC crate");
    IdlParser::parse(Rule::interface, include_str!("idl/srvsvc.idl"))
        .expect("Failed to parse IDL")
        .for_each(|pair| {
            println!("{:?}", pair);
        });
}
