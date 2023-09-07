use std::{fs::File, path::Path, io::{BufWriter, Write}};
use actix::{Actor, Context, Handler};

use super::EncodedUpdate;

pub struct Logger {
    log_writer: BufWriter<File>
}

impl Handler<EncodedUpdate> for Logger {
    type Result = ();

    fn handle(&mut self, msg: EncodedUpdate, _ctx: &mut Self::Context) -> Self::Result {
        let _ = self.log_writer.write_all(&(msg.inner.len() as u32).to_le_bytes()); // Save a few bytes on the size (a single sample won't exceed 4GB)
        let _ = self.log_writer.write_all(&msg.inner);
    }
}

impl Logger {
    pub fn new(
        log_file_path: &Path,
        user_period: u64
    ) -> anyhow::Result<Self> {
        let mut log_writer = BufWriter::new(File::create(log_file_path)?);
        
        // Write header
        log_writer.write_all(&user_period.to_le_bytes())?;
        
        Ok(Self {
            log_writer
        })
    }
}

impl Actor for Logger {
    type Context = Context<Self>;
}
