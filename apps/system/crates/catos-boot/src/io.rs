use std::path::Path;

pub(crate) fn read_target_file_checked(
    root: &Path,
    relative: &str,
) -> Result<Option<String>, String> {
    let rooted = format!("/{relative}");
    match catos_target::execute::confined::read_rooted_file(root, &rooted) {
        Ok(contents) => String::from_utf8(contents)
            .map(Some)
            .map_err(|error| format!("target {rooted} is not UTF-8: {error}")),
        Err(catos_target::FsError::NotFound) => Ok(None),
        Err(error) => Err(format!("cannot read target {rooted}: {error}")),
    }
}

pub(crate) fn has_target_path_checked(root: &Path, relative: &str) -> Result<bool, String> {
    use catos_target::execute::confined::{rooted_path_kind, RootedPathKind};

    let rooted = format!("/{relative}");
    match rooted_path_kind(root, &rooted) {
        Ok(None) | Err(catos_target::FsError::NotFound) => Ok(false),
        Ok(Some(RootedPathKind::Symlink)) => Err(format!("target path {rooted} is a symlink")),
        Ok(Some(_)) => Ok(true),
        Err(error) => Err(format!("cannot inspect target path {rooted}: {error}")),
    }
}

pub(crate) fn read_target_file(root: &Path, relative: &str) -> Option<String> {
    read_target_file_checked(root, relative).ok().flatten()
}
