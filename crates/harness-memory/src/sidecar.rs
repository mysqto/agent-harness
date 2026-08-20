//! The sidecar's record protocol: one JSON line out, one JSON line back.
//!
//! Writes go through the sidecar rather than direct because it holds the signing key and seals on
//! our behalf, so this process needs no key material of its own. It also owns a spool, which is why
//! an ack has more than two outcomes.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{Error, Result, http};

/// One line of acknowledgement.
#[derive(Debug, Deserialize)]
struct Ack {
    /// One of `accepted`, `spooled`, `rejected`, `spool_full`, `error`.
    status: String,
    /// Why, when the sidecar cares to say.
    #[serde(default)]
    detail: Option<String>,
}

/// Sends one record line and interprets the ack, within `budget`.
pub(crate) async fn submit(socket: &Path, record: &[u8], budget: Duration) -> Result<()> {
    tokio::time::timeout(budget, exchange(socket, record))
        .await
        .map_err(|_| {
            Error::Unavailable(format!(
                "sidecar did not acknowledge within {}ms",
                budget.as_millis()
            ))
        })?
}

/// Writes the line, reads the ack.
async fn exchange(socket: &Path, record: &[u8]) -> Result<()> {
    let stream = http::connect_unix(socket).await?;
    let mut stream = BufReader::new(stream);
    stream
        .write_all(record)
        .await
        .map_err(|err| Error::Transport(format!("write record: {err}")))?;
    // The newline is the frame: without it the sidecar is still waiting for the rest of the record.
    stream
        .write_all(b"\n")
        .await
        .map_err(|err| Error::Transport(format!("write record: {err}")))?;
    stream
        .flush()
        .await
        .map_err(|err| Error::Transport(format!("flush record: {err}")))?;

    let mut line = String::new();
    let read = stream
        .read_line(&mut line)
        .await
        .map_err(|err| Error::Transport(format!("read ack: {err}")))?;
    if read == 0 {
        // Nothing was said, so nothing is known: the record may or may not be spooled.
        return Err(Error::Transport(
            "sidecar closed before acknowledging".into(),
        ));
    }
    interpret(&line)
}

/// Maps an ack line onto an outcome.
fn interpret(line: &str) -> Result<()> {
    let ack: Ack = serde_json::from_str(line.trim())
        .map_err(|err| Error::Transport(format!("malformed ack `{}`: {err}", line.trim())))?;
    let detail = ack.detail.unwrap_or_else(|| ack.status.clone());
    match ack.status.as_str() {
        // `spooled` means durably queued: the sidecar owns delivery from here, so reporting a
        // failure would make the caller write the record twice.
        "accepted" | "spooled" => Ok(()),
        "rejected" => Err(Error::Rejected(detail)),
        // A full spool and an internal error are both temporary from here — the record is not
        // wrong, so the caller should retry rather than fix it.
        "spool_full" | "error" => Err(Error::Unavailable(detail)),
        other => Err(Error::Transport(format!(
            "unrecognised ack status `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::interpret;
    use crate::Error;

    #[test]
    fn accepted_and_spooled_both_succeed() {
        interpret("{\"status\":\"accepted\"}").expect("accepted");
        interpret("{\"status\":\"spooled\",\"detail\":\"queued\"}\n").expect("spooled");
    }

    #[test]
    fn rejected_is_permanent_and_the_rest_are_not() {
        assert!(matches!(
            interpret("{\"status\":\"rejected\",\"detail\":\"unknown entity kind\"}"),
            Err(Error::Rejected(detail)) if detail == "unknown entity kind"
        ));
        assert!(matches!(
            interpret("{\"status\":\"spool_full\"}"),
            Err(Error::Unavailable(detail)) if detail == "spool_full"
        ));
        assert!(matches!(
            interpret("{\"status\":\"error\",\"detail\":\"disk\"}"),
            Err(Error::Unavailable(detail)) if detail == "disk"
        ));
    }

    #[test]
    fn an_unusable_ack_is_a_transport_failure_not_a_panic() {
        for line in ["not json at all\n", "{\"status\":7}", "", "{}"] {
            assert!(
                matches!(interpret(line), Err(Error::Transport(_))),
                "{line}"
            );
        }
        assert!(matches!(
            interpret("{\"status\":\"who knows\"}"),
            Err(Error::Transport(_))
        ));
    }
}
