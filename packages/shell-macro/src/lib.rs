use proc_macro_hack::proc_macro_hack;

#[proc_macro_hack]
pub use shell_macro_impl::shell;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(shell!("echo \"what the fuck\"").trim(), "what the fuck")
    }
}
