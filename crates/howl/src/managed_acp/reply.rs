use std::{io, sync::Mutex};

use agent_client_protocol::{v1::schema as v1, v2::schema as v2};
use tokio::sync::{broadcast, oneshot};

use super::Event;

const MAX_REPLY: usize = 16 * 1024;

pub(super) struct TurnEvents {
    stream: broadcast::Sender<Event>,
    output: Mutex<Option<Capture>>,
}

impl TurnEvents {
    pub(super) fn new(stream: broadcast::Sender<Event>) -> Self {
        Self {
            stream,
            output: Mutex::new(None),
        }
    }

    pub(super) fn begin(&self, sender: Option<oneshot::Sender<io::Result<String>>>) {
        *self.output.lock().unwrap() = sender.map(|sender| Capture {
            buffer: ReplyBuffer::default(),
            sender,
        });
    }

    pub(super) fn send(&self, event: Event) {
        let mut output = self.output.lock().unwrap();
        if let Some(capture) = output.as_mut()
            && let Err(error) = capture.buffer.receive(&event)
            && let Some(capture) = output.take()
        {
            let _ = capture.sender.send(Err(error));
        }
        drop(output);
        let _ = self.stream.send(event);
    }

    pub(super) fn finish(&self) {
        if let Some(capture) = self.output.lock().unwrap().take() {
            let _ = capture.sender.send(capture.buffer.finish());
        }
    }
}

struct Capture {
    buffer: ReplyBuffer,
    sender: oneshot::Sender<io::Result<String>>,
}

#[derive(Default)]
struct ReplyBuffer {
    v1: String,
    v2: Vec<(v2::MessageId, String)>,
}

impl ReplyBuffer {
    fn receive(&mut self, event: &Event) -> io::Result<()> {
        match event {
            Event::Update(update) => {
                if let v1::SessionUpdate::AgentMessageChunk(chunk) = &update.update
                    && let v1::ContentBlock::Text(text) = &chunk.content
                {
                    append(&mut self.v1, &text.text)?;
                }
            }
            Event::UpdateV2(update) => match &update.update {
                v2::SessionUpdate::AgentMessageChunk(chunk) => {
                    if let v2::ContentBlock::Text(text) = &chunk.content {
                        append(self.message(&chunk.message_id)?, &text.text)?;
                    }
                }
                v2::SessionUpdate::AgentMessage(message) if !message.content.is_undefined() => {
                    let current = self.message(&message.message_id)?;
                    current.clear();
                    for block in message.content.value().into_iter().flatten() {
                        if let v2::ContentBlock::Text(text) = block {
                            append(current, &text.text)?;
                        }
                    }
                }
                _ => return Ok(()),
            },
            _ => return Ok(()),
        }
        if self.v2.iter().map(|(_, text)| text.len()).sum::<usize>()
            + self.v2.len().saturating_sub(1)
            > MAX_REPLY
        {
            return Err(invalid("agent reply exceeds the workflow limit"));
        }
        Ok(())
    }

    fn message(&mut self, id: &v2::MessageId) -> io::Result<&mut String> {
        let index = match self.v2.iter().position(|(known, _)| known == id) {
            Some(index) => index,
            None if self.v2.len() < 64 => {
                self.v2.push((id.clone(), String::new()));
                self.v2.len() - 1
            }
            None => return Err(invalid("agent reply contains too many messages")),
        };
        Ok(&mut self.v2[index].1)
    }

    fn finish(self) -> io::Result<String> {
        let text = if self.v2.is_empty() {
            self.v1
        } else {
            self.v2
                .into_iter()
                .map(|(_, text)| text)
                .collect::<Vec<_>>()
                .join("\n")
        };
        if text.trim().is_empty() {
            return Err(invalid("agent returned an empty reply"));
        }
        Ok(text)
    }
}

fn append(output: &mut String, text: &str) -> io::Result<()> {
    if output.len() + text.len() > MAX_REPLY {
        return Err(invalid("agent reply exceeds the workflow limit"));
    }
    output.push_str(text);
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_event(text: &str) -> Event {
        Event::Update(Box::new(v1::SessionNotification::new(
            "session",
            v1::SessionUpdate::AgentMessageChunk(v1::ContentChunk::new(text.into())),
        )))
    }

    #[test]
    fn a_stalled_reader_gets_all_chunks_and_an_oversized_reply_fails_before_turn_end() {
        let (stream, mut observer) = broadcast::channel(2);
        let events = TurnEvents::new(stream);
        let (sender, mut output) = oneshot::channel();
        events.begin(Some(sender));
        for chunk in ["a", "b", "c", "d"] {
            events.send(text_event(chunk));
        }
        assert!(matches!(
            observer.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(2))
        ));
        events.finish();
        assert_eq!(output.try_recv().unwrap().unwrap(), "abcd");

        let (sender, mut output) = oneshot::channel();
        events.begin(Some(sender));
        events.send(text_event(&"x".repeat(MAX_REPLY)));
        events.send(text_event("y"));
        assert_eq!(
            output.try_recv().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        events.finish();
    }
}
