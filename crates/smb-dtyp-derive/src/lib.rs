use proc_macro::TokenStream;

/// A helper macro that invokes `modular_bitfield` and `binrw` derives for bitfield structs.
/// Those must be installed as dependencies in the crate where this macro is used.
///
/// Adds derives for `Debug`, `Default`, `Clone`, `Copy`, `PartialEq`, and `Eq`.
#[proc_macro_attribute]
pub fn mbitfield(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::ItemStruct);
    quote::quote! {
        #[::modular_bitfield::bitfield]
        #[derive(::binrw::BinWrite, ::binrw::BinRead)]
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        #[bw(map = |&x| Self::into_bytes(x))]
        #[br(map = Self::from_bytes)]
        #input
    }
    .into()
}
