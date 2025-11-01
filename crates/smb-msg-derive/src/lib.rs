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
    // #[br(assert(_structure_size == #size))]
    // _structure_size: u16,
    syn::Field {
        attrs: vec![
            syn::parse_quote! {
                #[bw(calc = #size)]
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
/// - Adding `binrw` attributes to the struct itself, depending on whether it's
///   a request or response, and the enabled features (server/client).
fn modify_smb_msg(msg_type: SmbMsgType, item: TokenStream, attr: TokenStream) -> TokenStream {
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

    let cfg_attrs = msg_type.get_attr();

    TokenStream::from(quote! {
        #cfg_attrs
        #[derive(Debug, PartialEq, Eq)]
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

/// Proc-macro for adding binrw attributes to SMB request structs.
///
/// Conditionally adds `BinRead` or `BinWrite` depending on server/client features.
#[proc_macro_attribute]
pub fn smb_request_binrw(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let to_add = SmbMsgType::Request.get_attr();
    TokenStream::from(quote! {
        #to_add
        #item
    })
}

/// Proc-macro for adding binrw attributes to SMB response structs.
///
/// Conditionally adds `BinRead` or `BinWrite` depending on server/client features.
#[proc_macro_attribute]
pub fn smb_response_binrw(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    let to_add = SmbMsgType::Response.get_attr();
    TokenStream::from(quote! {
        #to_add
        #item
    })
}
