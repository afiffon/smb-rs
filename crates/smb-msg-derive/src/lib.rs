//! Utility macros for building SMB messages.
//!
//! This should be used only within the `smb-msg` crate.
//! Common utlities shall be placed in `smb-dtyp-derive` and re-exprorted in `smb-dtyp`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    DeriveInput, Expr, ExprLit, Fields, ItemStruct, Lit, Meta,
    parse::{Parse, ParseStream, Result},
    parse_macro_input,
};

enum SmbMsgType {
    Request,
    Response,
    Both,
}

impl SmbMsgType {
    /// Returns custom attributes for the SMB message type.
    ///
    /// Those shall be put before the message struct definition.
    fn get_attr(&self) -> proc_macro2::TokenStream {
        match self {
            SmbMsgType::Request => quote! {
                #[cfg_attr(all(feature = "server", feature = "client"), ::binrw::binrw)]
                #[cfg_attr(all(feature = "server", not(feature = "client")), ::binrw::binread)]
                #[cfg_attr(all(not(feature = "server"), feature = "client"), ::binrw::binwrite)]
            },
            SmbMsgType::Response => quote! {
                #[cfg_attr(all(feature = "server", feature = "client"), ::binrw::binrw)]
                #[cfg_attr(all(feature = "server", not(feature = "client")), ::binrw::binwrite)]
                #[cfg_attr(all(not(feature = "server"), feature = "client"), ::binrw::binread)]
            },
            SmbMsgType::Both => quote! {
                #[::binrw::binrw]
            },
        }
    }
}

#[derive(Debug)]
struct SmbReqResAttr {
    value: u16,
}

impl Parse for SmbReqResAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let meta: Meta = input.parse()?;

        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("size") => {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Int(lit), ..
                }) = nv.value
                {
                    let value: u16 = lit.base10_parse()?;
                    Ok(SmbReqResAttr { value })
                } else {
                    Err(syn::Error::new_spanned(
                        nv.value,
                        "expected integer literal",
                    ))
                }
            }
            _ => Err(syn::Error::new_spanned(meta, "expected `size = <u16>`")),
        }
    }
}

fn make_size_field(size: u16) -> syn::Field {
    // #[bw(calc = #size)]
    // #[br(temp)]
    // #[br(assert(_structure_size == #size))]
    // _structure_size: u16,
    syn::Field {
        attrs: vec![
            syn::parse_quote! {
                #[bw(calc = #size)]
            },
            syn::parse_quote! {
                #[br(temp)]
            },
            syn::parse_quote! {
                #[br(assert(_structure_size == #size))]
            },
        ],
        vis: syn::Visibility::Inherited,
        ident: Some(syn::Ident::new(
            "_structure_size",
            proc_macro2::Span::call_site(),
        )),
        colon_token: Some(syn::token::Colon {
            spans: [proc_macro2::Span::call_site()],
        }),
        ty: syn::parse_quote! { u16 },
        mutability: syn::FieldMutability::None,
    }
}

/// Implementation for the [`smb_request`] and [`smb_response`] macros.
///
/// This function expands the input struct by:
/// - Adding a `_structure_size: u16` field at the beginning of the struct,
///   with appropriate `binrw` attributes to calculate and assert its value.
fn modify_smb_msg(msg_type: SmbMsgType, item: TokenStream, attr: TokenStream) -> TokenStream {
    let item = common_struct_changes(msg_type, item);

    let mut item = parse_macro_input!(item as ItemStruct);
    let attr = parse_macro_input!(attr as SmbReqResAttr);

    let size_field = make_size_field(attr.value);
    match item.fields {
        Fields::Named(ref mut fields) => {
            fields.named.insert(0, size_field);
        }
        _ => {
            return syn::Error::new_spanned(
                &item.fields,
                "Expected named fields for smb request/response",
            )
            .to_compile_error()
            .into();
        }
    }

    TokenStream::from(quote! {
        #item
    })
}

/// Performs common changes to binrw structs.
///
/// - Adding `binrw` attributes to the struct itself, depending on whether it's
///   a request or response, and the enabled features (server/client).
/// - Modifying any field named `reserved` to have `#[br(temp)]` and `#[bw(calc = Default::default())]` attributes.
fn common_struct_changes(msg_type: SmbMsgType, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);

    let is_struct = matches!(input.data, syn::Data::Struct(_));

    let cfg_attrs = msg_type.get_attr();
    let output_all = TokenStream::from(quote! {
        #cfg_attrs
        #[derive(Debug, PartialEq, Eq)]
        #input
    });

    if !is_struct {
        return output_all;
    }

    let mut item = parse_macro_input!(output_all as ItemStruct);

    if let Fields::Named(ref mut fields) = item.fields {
        for field in fields.named.iter_mut() {
            if field.ident.as_ref().is_some_and(|id| *id == "reserved") {
                if field.vis != syn::Visibility::Inherited {
                    return syn::Error::new_spanned(
                        &field.vis,
                        "reserved field must have no visibility defined",
                    )
                    .to_compile_error()
                    .into();
                }

                // Put a new, unique name for the field to avoid conflicts.
                let line_number = proc_macro2::Span::call_site().start().line;
                field.ident = Some(syn::Ident::new(
                    &format!("_reserved{}", line_number),
                    proc_macro2::Span::call_site(),
                ));

                // Add attributes to the reserved field.
                field.attrs.push(syn::parse_quote! {
                    #[br(temp)]
                });

                // If type is [u8; N], we can set it to zeroed array. Otherwise, use Default::default().
                let default_bw_calc = if let syn::Type::Array(arr) = &field.ty {
                    let len = arr.len.clone();
                    syn::parse_quote! {
                        #[bw(calc = [0; #len])]
                    }
                } else {
                    syn::parse_quote! {
                        #[bw(calc = Default::default())]
                    }
                };

                field.attrs.push(default_bw_calc);
            }
        }
    }

    TokenStream::from(quote! {
        #item
    })
}

/// Proc-macro for constructing SMB request messages.
///
/// Valid usage is `#[smb_request(size = <u16>)]` before a struct definition.
#[proc_macro_attribute]
pub fn smb_request(attr: TokenStream, input: TokenStream) -> TokenStream {
    modify_smb_msg(SmbMsgType::Request, input, attr)
}

/// Proc-macro for constructing SMB response messages.
///
/// Valid usage is `#[smb_response(size = <u16>)]` before a struct definition.
#[proc_macro_attribute]
pub fn smb_response(attr: TokenStream, input: TokenStream) -> TokenStream {
    modify_smb_msg(SmbMsgType::Response, input, attr)
}

/// Proc-macro for constructing SMB request and response messages.
///
/// Valid usage is `#[smb_request_response(size = <u16>)]` before a struct definition.
#[proc_macro_attribute]
pub fn smb_request_response(attr: TokenStream, input: TokenStream) -> TokenStream {
    modify_smb_msg(SmbMsgType::Both, input, attr)
}

/// Proc-macro for adding binrw attributes to SMB request structs.
///
/// Conditionally adds `BinRead` or `BinWrite` depending on server/client features.
#[proc_macro_attribute]
pub fn smb_request_binrw(_attr: TokenStream, input: TokenStream) -> TokenStream {
    common_struct_changes(SmbMsgType::Request, input)
}

/// Proc-macro for adding binrw attributes to SMB response structs.
///
/// Conditionally adds `BinRead` or `BinWrite` depending on server/client features.
#[proc_macro_attribute]
pub fn smb_response_binrw(_attr: TokenStream, input: TokenStream) -> TokenStream {
    common_struct_changes(SmbMsgType::Response, input)
}

/// Proc-macro for adding binrw attributes to SMB request and response structs.
///
/// Adds both `BinRead` and `BinWrite` attributes.
#[proc_macro_attribute]
pub fn smb_message_binrw(_attr: TokenStream, input: TokenStream) -> TokenStream {
    common_struct_changes(SmbMsgType::Both, input)
}
