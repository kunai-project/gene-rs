use proc_macro::TokenStream;
use quote::{quote, quote_spanned};
use std::collections::HashMap;
use syn::{
    parse_macro_input, parse_quote, punctuated::Punctuated, spanned::Spanned, Attribute,
    DataStruct, DeriveInput, Expr, Generics, Meta, MetaNameValue, Token, TypeParam, WhereClause,
};

/// helper macro to get the expected syn::Lit enum variant from a syn::Expr
/// # Example
///
/// ```rust,ignore
/// let arg: syn::Expr = ... ;
/// expect_lit_variant!(arg, syn::Lit::Str)
/// ```
macro_rules! expect_lit_variant {
    ($expr: expr, $lit_variant:path) => {
        match $expr {
            syn::Expr::Lit(lit_expr) => match lit_expr.lit {
                $lit_variant(v) => Some(v),
                _ => None,
            },
            _ => None,
        }
    };
}

struct MetaParser {
    attr: syn::Attribute,
    metas: HashMap<String, Meta>,
}

impl MetaParser {
    fn parse_meta(attr: &Attribute) -> Result<Self, syn::Error> {
        let mut out = HashMap::new();

        let nested = attr
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_err(|_| syn::Error::new_spanned(attr, "failed to parse attribute meta"))?;

        for meta in nested {
            out.insert(
                meta.path()
                    .get_ident()
                    .ok_or(syn::Error::new_spanned(
                        meta.clone(),
                        "failed to process meta",
                    ))?
                    .to_string(),
                meta,
            );
        }
        Ok(Self {
            attr: attr.clone(),
            metas: out,
        })
    }

    fn contains_key(&self, key: &str) -> bool {
        self.metas.contains_key(key)
    }

    fn get_key_value(&self, key: &str) -> Result<Option<&MetaNameValue>, syn::Error> {
        if let Some(meta) = self.metas.get(key) {
            match meta {
                Meta::NameValue(m) => return Ok(Some(m)),
                _ => {
                    return Err(syn::Error::new_spanned(
                        &self.attr,
                        format!("expecting a key value attribute: {key}"),
                    ))
                }
            }
        }
        Ok(None)
    }
}

struct EventDerive {
    input: DeriveInput,
    id: Option<Expr>,
    source: Option<Expr>,
}

impl EventDerive {
    fn parse_event_derive(input: DeriveInput) -> Result<Self, syn::Error> {
        let attrs = &input.attrs;

        let event_attr =
            attrs
                .iter()
                .find(|a| a.path().is_ident("event"))
                .ok_or(syn::Error::new_spanned(
                    &input,
                    "attribute #[event(id = Expr, source = Expr)] missing",
                ))?;

        let meta_attrs = MetaParser::parse_meta(event_attr)?;

        let id = Some(
            meta_attrs
                .get_key_value("id")?
                .cloned()
                .map(|meta| meta.value)
                .ok_or(syn::Error::new_spanned(
                    event_attr.path(),
                    "id = Expr missing",
                ))?,
        );

        let source = Some(
            meta_attrs
                .get_key_value("source")?
                .cloned()
                .map(|meta| meta.value)
                .ok_or(syn::Error::new_spanned(
                    event_attr.path(),
                    "source = Expr missing",
                ))?,
        );

        Ok(EventDerive { input, id, source })
    }

    fn expand_event(&self) -> proc_macro2::TokenStream {
        let struct_name = &self.input.ident;
        let generics = &self.input.generics;
        let generic_trait_bound = FieldGetterDerive::field_getter_where_clause(generics);

        let impl_id = self
            .id
            .clone()
            .map(|id| {
                quote! {
                    #[inline(always)]
                    fn id(&self) -> i64 {
                        #id
                    }
                }
            })
            .unwrap_or_default();

        let impl_source = self
            .source
            .clone()
            .map(|source| {
                quote! {
                    #[inline(always)]
                    fn source(&self) -> std::borrow::Cow<'_,str> {
                        #source
                    }
                }
            })
            .unwrap_or_default();

        let expanded = quote! {
            impl #generics Event for #struct_name #generics #generic_trait_bound{

                #impl_id

                #impl_source
            }
        };

        expanded
    }
}

/// Derives [Event](/gene/trait.Event.html) trait. It is required to also implement [FieldGetter](/gene/trait.FieldGetter.html).
///
/// **NB:** `FieldGetter` can be derived with [FieldGetter] derive macro
///
/// # Structure Attributes
///
/// `#[event(id = expr, source = expr)]` both `id` and `source` are mandatory to respectively
/// implement the `fn id() -> i64` and `fn source() -> Cow<'_, str>` from trait
///
/// # Example
///
/// ```rust
/// use gene_derive::{Event, FieldGetter};
/// use gene::{Event,FieldGetter,FieldValue};
/// use std::borrow::Cow;
///
/// #[derive(Event, FieldGetter)]
/// #[event(id = self.event_id, source = "whatever".into())]
/// struct LogEvent<T> {
///     name: String,
///     some_field: u32,
///     event_id: i64,
///     some_gen: T,
/// }
/// ```
#[proc_macro_derive(Event, attributes(event))]
pub fn event_derive(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    match EventDerive::parse_event_derive(input)
        .map(|ed| ed.expand_event().into())
        .map_err(|e| e.to_compile_error().into())
    {
        Ok(ts) => ts,
        Err(ts) => ts,
    }
}

struct FieldGetterDerive {
    input: DeriveInput,
    use_serde_rename: bool,
    get_arms: Vec<proc_macro2::TokenStream>,
}

impl FieldGetterDerive {
    fn build_match_arms(mut self, data_struct: &DataStruct) -> Result<Self, syn::Error> {
        // we iterate over the enum variants
        for field in data_struct.fields.iter() {
            // name of the variant
            let field_name = &field.ident;
            let field_type = &field.ty;
            let span = field_type.span();
            let mut fields = vec![quote!(stringify!(#field_name))];

            // we take serde(rename = "foo") into account if #[getter(use_serde_rename = true)]
            // is specified in structure
            if let Some(attr) = field.attrs.iter().find(|a| {
                a.path().is_ident("getter") || (a.path().is_ident("serde") && self.use_serde_rename)
            }) {
                let attrs = MetaParser::parse_meta(attr)?;

                // specific processing if event attribute
                if attr.path().is_ident("getter") && attrs.contains_key("skip") {
                    continue;
                }

                if let Some(arg) = attrs
                    .get_key_value("rename")?
                    .cloned()
                    .map(|meta| meta.value)
                {
                    let new_name = expect_lit_variant!(arg, syn::Lit::Str).ok_or(
                        syn::Error::new_spanned(attr, "rename expects literal string"),
                    )?;
                    fields.push(quote!(#new_name));
                }
            }

            self.get_arms.push(quote_spanned! {
            span =>
            #(#fields)|* => {
                #[allow(clippy::redundant_closure_call)]
                |x: &dyn FieldGetter, i: core::slice::Iter<'_, std::string::String>| -> Option<FieldValue> {
                    x.get_from_iter(i)
                }(&self.#field_name, i)
            }});
        }
        Ok(self)
    }

    fn field_getter_where_clause(generics: &Generics) -> Option<WhereClause> {
        //let generics = &self.input.generics;
        // the other predicates in where clause of the structure
        let predicates = generics
            .where_clause
            .as_ref()
            .map(|wc| wc.predicates.clone());
        let type_params = generics.type_params().cloned().collect::<Vec<TypeParam>>();

        if type_params.is_empty() {
            return None;
        }

        // we want any generic used in the structure to implement PartialEvent
        parse_quote! {
            where
                #(#type_params: FieldGetter,)*
                #predicates
        }
    }

    fn parse_field_getter_derive(input: DeriveInput) -> Result<Self, syn::Error> {
        let mut use_serde_rename_flag = false;

        let data_struct = match &input.data {
            syn::Data::Struct(data_struct) => data_struct,
            _ => return Err(syn::Error::new_spanned(&input, "")),
        };

        if let Some(attr) = input
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("getter"))
        {
            let args = MetaParser::parse_meta(attr)?;
            use_serde_rename_flag = args.contains_key("use_serde_rename");
        }

        FieldGetterDerive {
            input: input.clone(),
            use_serde_rename: use_serde_rename_flag,
            get_arms: vec![],
        }
        .build_match_arms(data_struct)
    }

    fn expand_partial_event(&self) -> proc_macro2::TokenStream {
        let struct_name = &self.input.ident;
        let generics = &self.input.generics;
        let arms = &self.get_arms;
        let generic_trait_bound = Self::field_getter_where_clause(&self.input.generics);

        let expand = quote! {
            impl #generics FieldGetter for #struct_name #generics #generic_trait_bound{
                #[inline(always)]
                fn get_from_iter(&self, mut i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue> {
                    let field = i.next()?;

                    match field.as_str() {
                        #(#arms)*
                        _ => None,
                    }
                }
            }
        };
        expand
    }
}

/// Derives [FieldGetter](/gene/trait.FieldGetter.html) trait
///
/// # Structure Attributes
///
/// `#[getter(use_serde_rename)]` can be used to parse `#[serde(rename)]` instead of duplicating
/// attributes on every field with `#[getter(rename = "...")]`
///
/// # Field Attributes
///
/// `#[getter(rename = "new_name")]` can be used to apply a new name to the field
///
/// `#[getter(skip)]` skip the field from being implemented. It is important to know
/// that any access to a skipped field will return [None]

#[proc_macro_derive(FieldGetter, attributes(getter))]
pub fn field_getter_derive(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    match FieldGetterDerive::parse_field_getter_derive(input)
        .map(|ed| ed.expand_partial_event().into())
        .map_err(|e| e.to_compile_error().into())
    {
        Ok(ts) => ts,
        Err(ts) => ts,
    }
}
