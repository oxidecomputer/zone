extern crate proc_macro;

use heck::{ToKebabCase, ToSnakeCase};
use proc_macro_error::{abort, proc_macro_error, ResultExt};
use quote::{format_ident, quote};
use syn::{
    self,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    DeriveInput, Ident, LitStr, Token,
};

/// Proc macro used for autogenerating "Scopes" from resource objects.
///
/// This crate is very tightly coupled with the "zone" crate; it injects
/// methods into the `zone::Config` object.
///
/// The following attribute macros may be used:
/// - resource(name = "NAME")
///   Allows setting a custom name for a field to be emitted to the zonecfg command.
/// - resource(selector)
///   Identifies that this field may be used to select the resource, as a
///   query parameter for searching across resources.
/// - resources(global)
///   (Can be attached to any field, it is parsed per-resource)
///   Identifies that this is the Global resource, which has some unique
///   handling.
///
/// For each resource, the following is generated:
/// - For non-global resources:
///     Config::add_{resource_name} to add a new resource.
///     Config::select_{resource_name}_by_{selector} for all selectors.
///     Config::remove_all_{resource} to remove a resource
///     Config::remove_{resource_name}_by_{selector} for all selectors.
/// - For the global resource:
///     Config::get_global to select the global resource.
/// - For all resources:
///     {resource_name}Scope, an object representing the scope,
///     which contains a collection of setters for each field.
///     Objects which can be cleared accept optional arguments; providing
///     `None` clears the parameter, providing `Some(...)` sets the parameter.
#[proc_macro_derive(Resource, attributes(resource))]
#[proc_macro_error]
pub fn derive_resource(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let input_name = input.ident;

    let data = match input.data {
        syn::Data::Struct(data) => data,
        _ => panic!("Resource only valid for structures"),
    };

    let fields = match data.fields {
        syn::Fields::Named(fields) => fields,
        _ => panic!("Named fields only"),
    };

    let mut global_attrs = GlobalAttrs { attrs: vec![] };

    let parsed_fields: Vec<ParsedField> = fields
        .named
        .into_iter()
        .map(|field| {
            let (globals, field_attrs) = parse_attributes(&field.attrs);
            global_attrs.attrs.extend(globals);
            ParsedField {
                field,
                attrs: field_attrs,
            }
        })
        .collect();

    let scope_name = get_scope_name(&input_name);

    // Within the scope object, provide setters.
    let scope_setters = setters(&scope_name, &parsed_fields);

    // Mechanism to construct/destroy scope.
    let scope_constructor = constructor(&input_name, &parsed_fields, &global_attrs);

    let scope_selectors = selectors(&input_name, &parsed_fields);

    let scope_msg = format!(
        "Generated scope for the [{}] resource.\n\n\
        This object represents the resource scope for a zone configuration, and
        automatically closes that scope when dropped.\n\n\
        To construct this object, refer to [Config::{}].",
        input_name,
        if global_attrs.is_global_resource() {
            format!("get_{}", input_name.to_string().to_snake_case())
        } else {
            format!("add_{}", input_name.to_string().to_snake_case())
        }
    );
    let tokens = quote! {
        // Auto-generated implementation of Scoped resource.

        #[doc = #scope_msg]
        pub struct #scope_name<'a> {
            config: &'a mut Config,
        }

        impl<'a> #scope_name<'a> {
            fn push(&mut self, arg: impl Into<String>) {
                self.config.push(arg.into())
            }
        }

        #scope_setters
        #scope_constructor
        #scope_selectors
    };
    proc_macro::TokenStream::from(tokens)
}

fn get_scope_name(input_name: &Ident) -> Ident {
    format_ident!("{}Scope", input_name)
}

// Within the scope object, provide setters.
fn setters(scope_name: &Ident, parsed_fields: &Vec<ParsedField>) -> proc_macro2::TokenStream {
    parsed_fields
        .iter()
        .map(|parsed| {
            let name = parsed.name();
            let ty = parsed.ty();
            let setter = format_ident!("set_{}", parsed.field_name());

            quote! {
                impl<'a> #scope_name<'a> {
                    pub fn #setter(&mut self, value: impl Into<#ty>) -> &mut Self {
                        let value: #ty = value.into();
                        for property in value.get_properties() {
                            let name = match &property.name {
                                PropertyName::Implicit => #name,
                                PropertyName::Explicit(name) => name,
                            };
                            self.push(format!("set {}={}", name, property.value));
                        }
                        for property_name in value.get_clearables() {
                            let name = match &property_name {
                                PropertyName::Implicit => #name,
                                PropertyName::Explicit(name) => name,
                            };
                            self.push(format!("clear {}", name));
                        }
                        self
                    }
                }
            }
        })
        .collect()
}

fn selectors(input_name: &Ident, parsed_fields: &Vec<ParsedField>) -> proc_macro2::TokenStream {
    let scope_name = get_scope_name(&input_name);
    let input_name_kebab = input_name.to_string().to_kebab_case();
    parsed_fields
        .iter()
        .map(|parsed| {
            if parsed.selector() {
                let name = parsed.name();
                let snake_input_name = input_name.to_string().to_snake_case();
                let ty = parsed.ty();
                let selector = format_ident!("select_{}_by_{}", snake_input_name, name,);
                let selector_msg = format!(
                    "Generated selector for the [{}] resource.\n\n\
                    Allows the selection of an existing resource for modification
                    with a matching value of [{}::{}].",
                    input_name,
                    input_name,
                    parsed.field_name(),
                );

                let remover = format_ident!("remove_{}_by_{}", snake_input_name, name,);
                let remover_msg = format!(
                    "Generated removal function for the [{}] resource\n\n\
                    Allows the removal of all existing resources with a matching
                    value of [{}::{}].",
                    input_name,
                    input_name,
                    parsed.field_name(),
                );
                quote! {
                    impl Config {
                        #[doc = #selector_msg]
                        pub fn #selector(&mut self, value: impl Into<#ty>) -> #scope_name {
                            let value: #ty = value.into();
                            let mut scope = #scope_name {
                                config: self
                            };
                            scope.push(
                                format!("select {} {}={}",
                                    #input_name_kebab,
                                    #name,
                                    value,
                                )
                            );
                            scope
                        }

                        #[doc = #remover_msg]
                        pub fn #remover(&mut self, value: impl Into<#ty>) {
                            let value: #ty = value.into();
                            self.push(
                                format!(
                                    "remove -F {} {}={}",
                                    #input_name_kebab,
                                    #name,
                                    value,
                                )
                            );
                        }

                    }
                }
            } else {
                quote! {}
            }
        })
        .collect()
}

// Create the mechanism to create/destroy the scope object.
fn constructor(
    input_name: &Ident,
    parsed_fields: &Vec<ParsedField>,
    global_attrs: &GlobalAttrs,
) -> proc_macro2::TokenStream {
    let scope_name = get_scope_name(&input_name);
    let input_name_snake = input_name.to_string().to_snake_case();
    let input_name_kebab = input_name.to_string().to_kebab_case();

    // Given:
    // - A scope object named "scope"
    // - A local named "values"
    //
    // Push back all possible values to the scope.
    let initial_set_values: proc_macro2::TokenStream = parsed_fields
        .iter()
        .map(|parsed| {
            let values = format_ident!("values");
            let field = parsed.field.ident.as_ref().unwrap();
            let name = parsed.name();
            quote! {
                for property in #values.#field.get_properties() {
                    let name = match &property.name {
                        PropertyName::Implicit => #name,
                        PropertyName::Explicit(name) => name,
                    };
                    scope.push(format!("set {}={}", name, property.value));
                }
            }
        })
        .collect();

    if global_attrs.is_global_resource() {
        let scope_get = format_ident!("get_{}", input_name_snake);
        let scope_get_msg = format!(
            "Acquire a reference to the global resource scope.
            This scope allows callers to safely set values within the [{}] object.",
            input_name
        );
        quote! {
            impl<'a> #scope_name<'a> {
                fn new(config: &'a mut Config) -> Self {
                    let mut scope = #scope_name {
                        config
                    };
                    scope
                }
            }

            impl Config {
                #[doc = #scope_get_msg]
                pub fn #scope_get(&mut self) -> #scope_name {
                    #scope_name::new(self)
                }
            }
        }
    } else {
        let scope_adder = format_ident!("add_{}", input_name_snake);
        let scope_adder_msg = format!(
            "Creates a new scope from a [{}] object. This begins
            specification for the resource, and returns an object which
            represents the new scope.",
            input_name
        );

        let scope_removal = format_ident!("remove_all_{}", input_name_snake);
        let scope_removal_msg = format!(
            "Deletes resources associated with the [{}] object.",
            input_name
        );

        quote! {
            impl<'a> Drop for #scope_name<'a> {
                /// Emits an "end" token, signifing the end of a resource scope.
                fn drop(&mut self) {
                    self.push("end".to_string());
                }
            }

            // Auto-generated bindings within the config object.
            impl Config {
                #[doc = #scope_adder_msg]
                pub fn #scope_adder(&mut self, values: &#input_name) -> #scope_name {
                    let mut scope = #scope_name {
                        config: self
                    };

                    scope.push(format!("add {}", #input_name_kebab));
                    #initial_set_values
                    scope
                }

                #[doc = #scope_removal_msg]
                pub fn #scope_removal(&mut self) {
                    self.push(format!("remove -F {}", #input_name_kebab));
                }
            }
        }
    }
}

struct GlobalAttrs {
    attrs: Vec<ResourceAttr>,
}

impl GlobalAttrs {
    fn is_global_resource(&self) -> bool {
        for attr in &self.attrs {
            if let ResourceAttr::Global(_) = attr {
                return true;
            }
        }
        false
    }
}

struct ParsedField {
    field: syn::Field,
    attrs: Vec<ResourceAttr>,
}

impl ParsedField {
    fn selector(&self) -> bool {
        for attr in &self.attrs {
            if let ResourceAttr::Selector(_) = attr {
                return true;
            }
        }
        false
    }

    fn field_name(&self) -> String {
        self.field.ident.as_ref().unwrap().to_string()
    }

    fn name(&self) -> String {
        for attr in &self.attrs {
            if let ResourceAttr::Name(_, s) = attr {
                return s.value();
            }
        }
        self.field_name()
    }

    fn ty(&self) -> proc_macro2::TokenStream {
        let ty = &self.field.ty;
        quote! { #ty }
    }
}

enum ResourceAttr {
    // Per-resource attributes
    Global(Ident),

    // Per-field attributes
    Selector(Ident),
    Name(Ident, LitStr),
}

impl Parse for ResourceAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        let name_str = name.to_string();

        if input.peek(Token![=]) {
            // skip '='
            let _ = input.parse::<Token![=]>()?;

            let lit: LitStr = input.parse()?;
            match name_str.as_ref() {
                "name" => Ok(ResourceAttr::Name(name, lit)),
                _ => abort!(name, "Unexpected attribute: {}", name_str),
            }
        } else {
            match name_str.as_ref() {
                "selector" => Ok(ResourceAttr::Selector(name)),
                "global" => Ok(ResourceAttr::Global(name)),
                _ => abort!(name, "Unexpected attribute: {}", name_str),
            }
        }
    }
}

fn parse_attributes(attrs: &[syn::Attribute]) -> (Vec<ResourceAttr>, Vec<ResourceAttr>) {
    attrs
        .iter()
        .filter(|attr| attr.path.is_ident("resource"))
        .flat_map(|attr| {
            attr.parse_args_with(Punctuated::<ResourceAttr, Token![,]>::parse_terminated)
                .unwrap_or_abort()
        })
        .partition(|attr| match attr {
            ResourceAttr::Global(_) => true,
            _ => false,
        })
}
