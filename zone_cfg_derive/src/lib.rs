extern crate proc_macro;

use heck::{SnakeCase, KebabCase};
use quote::{format_ident, quote};
use proc_macro_error::{abort, proc_macro_error, ResultExt};
use syn::{
    self,
    parse_macro_input,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    DeriveInput, Ident, LitStr, Token
};

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

    let parsed_fields: Vec<ParsedField> = fields
            .named
            .into_iter()
            .map(|field| {
                let attrs = parse_attributes(&field.attrs);
                ParsedField {
                    field,
                    attrs,
                }
            })
            .collect();

    let scope_name = format_ident!("{}Scope", input_name);
    let input_name_snake = input_name.to_string().to_snake_case();
    let input_name_kebab = input_name.to_string().to_kebab_case();

    eprintln!("Parsing: {}", input_name);

    // Given:
    // - A scope object named "scope"
    // - A local named "values"
    //
    // Push back all possible values to the scope.
    let initial_set_values: proc_macro2::TokenStream = parsed_fields.iter()
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

    // Within the scope object, provide setters.
    let scope_setters: proc_macro2::TokenStream = parsed_fields.iter()
        .map(|parsed| {
            let name = parsed.name();
            let ty = parsed.ty();
            let setter = format_ident!("set_{}", parsed.field_name());

            quote! {
                pub fn #setter<T: Into<#ty>>(&mut self, value: T) {
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
                }
            }
        })
        .collect();

    // Generated code:
    let scope_msg = format!(
        "Generated scope for [{}]. This object represents the resource scope for a zone
         configuration, and automatically closes that scope when dropped.",
        input_name.to_string()
    );
    let scope_adder = format_ident!("add_{}", input_name_snake);
    let scope_adder_msg = format!(
        "Creates a new scope from a [{}] object. This begins specification for the resource,
         and returns an object which represents the new scope.",
        input_name.to_string()
    );
    let tokens = quote! {
        // Auto-generated implementation of Scoped resource.

        #[doc = #scope_msg]
        pub struct #scope_name<'a> {
            config: &'a mut Config,
        }

        impl<'a> #scope_name<'a> {
            fn push<S: Into<String>>(&mut self, arg: S) {
                self.config.args.push(arg.into())
            }

            fn add(config: &'a mut Config, values: &#input_name)
                -> Self {
                let mut scope = #scope_name {
                    config
                };

                scope.push(format!("add {}", #input_name_kebab));
                #initial_set_values
                scope
            }

            #scope_setters
        }

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
                #scope_name::add(self, values)
            }
        }
    };
    proc_macro::TokenStream::from(tokens)
}

struct ParsedField {
    field: syn::Field,
    attrs: Vec<ResourceAttr>,
}

impl ParsedField {
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
                _ => abort!(name, "Unexpected attribute: {}", name_str)
            }
        } else {
            match name_str.as_ref() {
                "selector" => Ok(ResourceAttr::Selector(name)),
                _ => abort!(name, "Unexpected attribute: {}", name_str)
            }
        }
    }
}

fn parse_attributes(attrs: &[syn::Attribute]) -> Vec<ResourceAttr> {
    attrs
        .iter()
        .filter(|attr| attr.path.is_ident("resource"))
        .flat_map(|attr| {
            attr.parse_args_with(Punctuated::<ResourceAttr, Token![,]>::parse_terminated)
                .unwrap_or_abort()
        })
        .collect()

}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
