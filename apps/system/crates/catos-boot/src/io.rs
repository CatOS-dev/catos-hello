use std::path::Path;

pub(crate) fn read_target_file(root: &Path, relative: &str) -> Option<String> {
    catos_target::execute::confined::read_rooted_file(root, &format!("/{relative}"))
        .ok()
        .and_then(|contents| String::from_utf8(contents).ok())
}

pub(crate) fn has_target_path(root: &Path, relative: &str) -> bool {
    catos_target::execute::confined::list_rooted_directory_names(root, &format!("/{relative}"))
        .is_ok()
}
