


use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "src/idl/idl.pest"]
pub struct IdlParser;