use crate::{
    FieldResultExtra,
    FileInfo,
    FieldInfo,
    Result,
    MulterError,
    Handler,
};
use actix_web::{
    http::header::ContentDisposition,
    web::block,
};
use futures::future::{LocalBoxFuture, FutureExt, TryFutureExt, try_join};
use log::error;
use rand::{Rng, thread_rng, distributions::Alphanumeric};
use std::{
    ffi::OsString,
    io::Write,
    iter,
    path::Path,
};
use tokio::stream::StreamExt;

pub struct FileResultInfo {
    info: FileInfo,
    accepted: bool,
}

impl FieldResultExtra for FileResultInfo {
    fn content(&self) -> Option<&[u8]> {
        None
    }
    fn file(&self) -> Option<&FileInfo> {
        Some(&self.info)
    }
    fn size(&self) -> usize {
        self.info.size
    }
    fn accept(&mut self) {
        self.accepted = true;
    }
}

impl Drop for FileResultInfo {
    fn drop(&mut self) {
        if !self.accepted {
            if let Err(e) = std::fs::remove_file(&self.info.path) {
                error!("failed to remove file {:?}", e);
            }
        }
    }
}

pub type PathGenerator = Box<dyn for<'a> Fn(&'a FieldInfo, Option<ContentDisposition>)
    -> LocalBoxFuture<'a, Result<OsString>>>;

pub struct FileStorageBuilder {
    max_size: Option<usize>,
    destination: Option<PathGenerator>,
    filename: Option<PathGenerator>,
    make_dirs: bool,
}

impl FileStorageBuilder {
    pub fn new() -> FileStorageBuilder {
        Self {
            max_size: None,
            destination: None,
            filename: None,
            make_dirs: false,
        }
    }
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = Some(size);
        self
    }
    pub fn destination(
        mut self,
        destination: PathGenerator,
    ) -> Self {
        self.destination = Some(destination);
        self
    }
    pub fn constant_destination(
        mut self,
        destination: OsString,
    ) -> Self {
        self.destination = Some(Box::new(move |_, _| {
            let destination = destination.clone();
            async move {
                Ok(destination.clone())
            }.boxed_local()
        }));
        self
    }
    pub fn filename(
        mut self,
        filename: PathGenerator
    ) -> Self {
        self.filename = Some(filename);
        self
    }
    pub fn origin_filename(mut self) -> Self {
        self.filename = Some(Box::new(|info, content_disposition| async move {
            let content_disposition = content_disposition
                .ok_or_else(|| MulterError::MissingContentDisposition)?;
            let filename = content_disposition.get_filename()
                .ok_or_else(|| MulterError::ExpectedFileField {
                    field: info.name.clone().into(),
                })?;
            Ok(sanitize_filename::sanitize(filename).into())
        }.boxed_local()));
        self
    }
    pub fn random_filename(mut self, length: usize) -> Self {
        self.filename = Some(Box::new(move |info, content_disposition| async move {
            let content_disposition = content_disposition
                .ok_or_else(|| MulterError::MissingContentDisposition)?;
            let extension = Path::new(content_disposition.get_filename()
                .ok_or_else(|| MulterError::ExpectedFileField {
                    field: info.name.clone().into(),
                })?)
                .extension()
                .map(|ext| ext.to_str()
                    .ok_or_else(|| MulterError::InvalidEncoding {
                        field: info.name.clone().into(),
                    }))
                .transpose()?;
            let mut rng = thread_rng();
            let mut filename: OsString = iter::repeat(())
                .map(|_| rng.sample(Alphanumeric))
                .take(length)
                .collect::<String>().into();
            if let Some(extension) = extension {
                filename.push(".");
                filename.push(sanitize_filename::sanitize(extension));
            }
            Ok(filename)
        }.boxed_local()));
        self
    }
    pub fn make_dirs(mut self) -> Self {
        self.make_dirs = true;
        self
    }
    pub fn build(self) -> Handler {
        let filename_generator = self.filename.expect("must have filename generator");
        let destination_generator = self.destination.expect("must have destination generator");
        let max_size = self.max_size;
        let make_dirs = self.make_dirs;
        Box::new(move |info, field| {
            try_join(filename_generator(info, field.content_disposition()),
                     destination_generator(info, field.content_disposition()))
                .and_then(move |(filename, destination)| async move {
                    let destination_copy = destination.clone();
                    if make_dirs {
                        block(move || std::fs::create_dir_all(destination_copy))
                            .await
                            .map_err(|e| MulterError::from(e))?;
                    }
                    let filepath = Path::new(&destination).join(&filename);
                    let path = OsString::from(filepath.clone());
                    let mut file = block(move || std::fs::File::create(filepath))
                        .await
                        .map_err(|e| MulterError::from(e))?;
                    let mut size: usize = 0;
                    while let Some(chunk) = field.next().await {
                        let data = chunk
                            .map_err(|e| MulterError::from(e))?;
                        size += data.len();
                        if let Some(max_size) = max_size {
                            if size > max_size {
                                if let Err(e) = std::fs::remove_file(&path) {
                                    error!("failed to remove file {}", e);
                                }
                                return Err(MulterError::MaxFieldContentLengthReached {
                                    field: info.name.clone().into(),
                                });
                            }
                        }
                        file = block(move || file.write_all(&data).map(|_| file))
                            .await
                            .map_err(|e| {
                                if let Err(e) = std::fs::remove_file(&path) {
                                    error!("failed to remove file {}", e);
                                }
                                MulterError::from(e)
                            })?;
                    }
                    drop(file);
                    Ok(Box::new(FileResultInfo {
                        info: FileInfo {
                            destination,
                            filename,
                            path,
                            size,
                        },
                        accepted: false,
                    }) as Box<dyn FieldResultExtra + std::marker::Send>)
                })
        }.boxed_local())
    }
}
