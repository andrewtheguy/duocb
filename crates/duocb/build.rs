fn main() {
    // Fluent on every platform: one consistent look (auto light/dark) instead
    // of per-OS style drift.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/main.slint", config).expect("slint build failed");
}
