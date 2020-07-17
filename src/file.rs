#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum File {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Default)]
pub struct FileSystem {
    files: Vec<File>,
}

impl FileSystem {
    pub fn from_fd(&self, fd: i64) -> Option<File> {
        match fd {
            0 => Some(File::Stdin),
            1 => Some(File::Stdout),
            2 => Some(File::Stderr),
            _ => None,
        }
    }
}
