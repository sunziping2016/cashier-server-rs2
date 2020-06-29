use crate::{
    FieldResultExtra,
    FileInfo,
    MulterError,
    Handler,
};
use bytes::BytesMut;
use futures::future::FutureExt;
use std::borrow::Borrow;
use tokio::stream::StreamExt;

pub struct MemoryResultInfo {
    data: BytesMut,
}

impl FieldResultExtra for MemoryResultInfo {
    fn content(&self) -> Option<&[u8]> {
        Some(self.data.borrow())
    }
    fn file(&self) -> Option<&FileInfo> {
        None
    }
    fn size(&self) -> usize {
        self.data.len()
    }
    fn accept(&mut self) {
        // do nothing
    }
}

pub struct MemoryStorageBuilder {
    max_size: Option<usize>,
}

impl Default for MemoryStorageBuilder {
    fn default() -> Self {
        Self {
            max_size: None
        }
    }
}

impl MemoryStorageBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = Some(size);
        self
    }
    pub fn build(self) -> Handler {
        let max_size = self.max_size;
        Box::new(move |info, field| async move {
            let mut result = BytesMut::new();
            while let Some(chunk) = field.next().await {
                let data = chunk
                    .map_err(MulterError::from)?;
                if let Some(max_size) = max_size {
                    if result.len() + data.len() > max_size {
                        return Err(MulterError::MaxFieldContentLengthReached {
                            field: info.name.clone().into(),
                        });
                    }
                }
                result.extend_from_slice(&data[..]);
            }
            Ok(Box::new(MemoryResultInfo {
                data: result,
            }) as Box<dyn FieldResultExtra + std::marker::Send>)
        }.boxed_local())
    }
}