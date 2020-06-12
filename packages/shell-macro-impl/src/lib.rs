extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro_hack::proc_macro_hack;
use quote::quote;
use std::process::Command;
use syn::parse::{Parse, ParseStream, Result};
use syn::parse_macro_input;
use syn::{LitStr};

#[derive(Debug)]
struct ShellArgs {
    command: String,
}

impl Parse for ShellArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let command: LitStr = input.parse()?;
        Ok(ShellArgs {
            command: command.value()
        })
    }
}

#[proc_macro_hack]
pub fn shell(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as ShellArgs);
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .arg("/C")
            .arg(args.command)
            .output()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(args.command)
            .output()
    };
    let output = output.expect("failed to execute process");
    if !output.status.success() {
        panic!("executed process return non-zero status code")
    }
    let output = std::str::from_utf8(&(output.stdout)[..]).expect("non-utf8 error?!");
    (quote! {
        {
            #output
        }
    }).into()
}
