//! Fallible stdout helpers so pipelines do not panic on a closed consumer.

use serde::Serialize;
use std::fmt;
use std::io::{self, Write};

pub fn line(arguments: fmt::Arguments<'_>) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_fmt(arguments)?;
    output.write_all(b"\n")?;
    Ok(())
}

pub fn json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}

pub fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
            || cause
                .downcast_ref::<serde_json::Error>()
                .is_some_and(|error| error.io_error_kind() == Some(io::ErrorKind::BrokenPipe))
    })
}

macro_rules! outln {
    ($($argument:tt)*) => {
        $crate::output::line(format_args!($($argument)*))
    };
}

pub(crate) use outln;
