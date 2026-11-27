use std::{io, path::Path};

use howl_envelope::{AgentRole, Body, Id};
use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;

use crate::{
    channel::Channel,
    delivery::{ChannelEvent, ChannelMessage, DeliveryStore, Device},
    enrollment::{ChannelPermission, profile::Profile},
    identity::LocalIdentity,
    node, workflow,
};

pub struct LocalInteraction<'a> {
    state: &'a Path,
}

#[derive(Serialize, JsonSchema)]
pub struct AgentAddress {
    pub id: String,
    pub device: String,
    pub role: &'static str,
    pub availability: &'static str,
}

#[derive(Serialize, JsonSchema)]
pub struct Message {
    pub message: String,
    pub sender: String,
    pub time: u64,
    pub text: String,
    pub role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_digest: Option<String>,
}

impl From<ChannelMessage> for Message {
    fn from(item: ChannelMessage) -> Self {
        let mut message = Self {
            message: hex::encode(item.message),
            sender: hex::encode(item.sender.device),
            time: item.received_at,
            text: String::new(),
            role: None,
            integration: item.integration.map(hex::encode),
            agent: None,
            target: None,
            in_reply_to: None,
            context_digest: None,
        };
        message.text = match item.body {
            Body::Chat(text) => text,
            Body::AgentReply(reply) => {
                message.role = Some(reply.role.name());
                message.agent = Some(hex::encode(reply.agent));
                message.in_reply_to = Some(hex::encode(reply.in_reply_to));
                message.context_digest = Some(hex::encode(reply.context_digest));
                reply.text
            }
            Body::Wake { session, text } => {
                message.role = Some("wake");
                message.target = Some(hex::encode(session));
                text
            }
        };
        message
    }
}

#[derive(Serialize, JsonSchema)]
pub struct Event {
    pub cursor: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(flatten)]
    pub message: Message,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct EventPage {
    pub events: Vec<Event>,
    pub cursor: u64,
    pub gap: bool,
    pub more: bool,
}

impl From<ChannelEvent> for Event {
    fn from(event: ChannelEvent) -> Self {
        Self {
            cursor: event.cursor,
            recipient: event
                .recipient
                .map(|recipient| hex::encode(recipient.device)),
            message: event.message.into(),
        }
    }
}

#[derive(Serialize, JsonSchema)]
pub struct Receipt {
    pub message: String,
}

pub struct Wake<'a> {
    pub channel: Id,
    pub peer: Id,
    pub route: &'a str,
    pub target: Id,
    pub lifetime: u16,
    pub text: &'a str,
}

impl<'a> LocalInteraction<'a> {
    pub fn new(state: &'a Path) -> Self {
        Self { state }
    }

    pub fn require_enrolled(&self) -> io::Result<()> {
        let identity = self.identity()?;
        let local = identity.certificate();
        let profile = Profile::load(self.state, &local)?
            .ok_or_else(|| denied("the local device must be enrolled"))?;
        profile.member(*local.device_id(), 0)?;
        Ok(())
    }

    pub fn authorize(&self, channel: Id, permission: ChannelPermission) -> io::Result<Channel> {
        let identity = self.identity()?;
        let channel = Channel::load(self.state, &identity, &channel)?;
        if !channel.allows(identity.certificate().device_id(), permission) {
            return Err(denied("local device lacks the signed channel permission"));
        }
        Ok(channel)
    }

    pub fn agents(&self, channel: Id) -> io::Result<Vec<AgentAddress>> {
        let channel = self.authorize(channel, ChannelPermission::Receive)?;
        Ok(channel
            .members()
            .iter()
            .flat_map(|peer| {
                [AgentRole::Architect, AgentRole::Reviewer].map(|role| AgentAddress {
                    id: hex::encode(role.agent_id(peer.device_id())),
                    device: hex::encode(peer.device_id()),
                    role: role.name(),
                    availability: "unknown",
                })
            })
            .collect())
    }

    pub(crate) fn history_messages(
        &self,
        channel: Id,
        limit: usize,
    ) -> io::Result<Vec<ChannelMessage>> {
        self.history_delivery(channel)?
            .0
            .channel_history(channel, limit)
            .map_err(io::Error::other)
    }

    pub fn history(&self, channel: Id, limit: usize) -> io::Result<Vec<Message>> {
        Ok(self
            .history_messages(channel, limit)?
            .into_iter()
            .rev()
            .map(Message::from)
            .collect())
    }

    pub fn events(&self, channel: Id, after: u64, limit: usize) -> io::Result<Vec<Event>> {
        self.authorize(channel, ChannelPermission::Receive)?;
        Ok(self
            .history_delivery(channel)?
            .0
            .channel_events(channel, after, limit)
            .map_err(io::Error::other)?
            .into_iter()
            .map(Event::from)
            .collect())
    }

    pub fn direct_events(
        &self,
        channel: Id,
        peer: Id,
        after: u64,
        limit: usize,
    ) -> io::Result<Vec<Event>> {
        let (delivery, local, peer) = self.direct_delivery(channel, peer)?;
        Ok(delivery
            .direct_events(channel, local, peer, after, limit)
            .map_err(io::Error::other)?
            .into_iter()
            .map(Event::from)
            .collect())
    }

    pub(crate) fn event_page(
        &self,
        channel: Id,
        peer: Option<Id>,
        after: u64,
        limit: usize,
    ) -> io::Result<EventPage> {
        self.require_enrolled()?;
        let (delivery, direct) = if let Some(peer) = peer {
            let (delivery, local, peer) = self.direct_delivery(channel, peer)?;
            (delivery, Some((local, peer)))
        } else {
            self.authorize(channel, ChannelPermission::Receive)?;
            (self.history_delivery(channel)?.0, None)
        };
        let page = delivery
            .event_page(channel, direct, after, limit)
            .map_err(io::Error::other)?;
        Ok(EventPage {
            events: page.events.into_iter().map(Event::from).collect(),
            cursor: page.cursor,
            gap: page.gap,
            more: page.more,
        })
    }

    pub fn status(&self, channel: Id) -> io::Result<serde_json::Value> {
        self.authorize(channel, ChannelPermission::Receive)?;
        self.history_status(channel)
    }

    pub(crate) fn history_status(&self, channel: Id) -> io::Result<serde_json::Value> {
        let status = self
            .history_delivery(channel)?
            .0
            .workflow_status(channel, node::unix_time()?)
            .map_err(io::Error::other)?;
        serde_json::to_value(status).map_err(io::Error::other)
    }

    pub(crate) fn delivery_status(
        &self,
        channel: Id,
        message: Id,
    ) -> io::Result<Vec<crate::delivery::DeliveryStatus>> {
        let (delivery, stream) = self.history_delivery(channel)?;
        delivery
            .delivery_status(stream, message)
            .map_err(io::Error::other)
    }

    pub async fn send(
        &self,
        channel: Id,
        peer: Id,
        route: &str,
        text: &str,
    ) -> io::Result<Receipt> {
        receipt(node::send(self.state, channel, peer, route, text).await?)
    }

    pub async fn wake(&self, wake: Wake<'_>) -> io::Result<Receipt> {
        receipt(
            node::send_wake(
                self.state,
                wake.channel,
                wake.peer,
                wake.route,
                wake.target,
                wake.lifetime,
                wake.text,
            )
            .await?,
        )
    }

    pub fn cancel(&self, channel: Id, root: Id) -> io::Result<()> {
        workflow::pause(self.state, channel, root)
    }

    fn identity(&self) -> io::Result<LocalIdentity> {
        LocalIdentity::load_or_create(self.state)
    }

    fn direct_delivery(
        &self,
        channel: Id,
        peer: Id,
    ) -> io::Result<(DeliveryStore, Device, Device)> {
        let roster = self.authorize(channel, ChannelPermission::Receive)?;
        let peer = roster
            .members()
            .iter()
            .find(|candidate| candidate.device_id() == &peer)
            .ok_or_else(|| denied("peer is outside the signed channel"))?;
        let (delivery, stream) = self.history_delivery(channel)?;
        let peer = node::device_for(self.state, peer)?;
        if peer == stream.sender {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct peer must be a different device",
            ));
        }
        Ok((delivery, stream.sender, peer))
    }

    fn history_delivery(
        &self,
        channel: Id,
    ) -> io::Result<(DeliveryStore, crate::delivery::Stream)> {
        node::history_delivery(self.state, &self.identity()?, channel)
    }
}

fn receipt(value: String) -> io::Result<Receipt> {
    let message = value
        .strip_prefix("queued ")
        .ok_or_else(|| io::Error::other("invalid mesh receipt"))?;
    let mut id = [0; 32];
    hex::decode_to_slice(message, &mut id).map_err(io::Error::other)?;
    Ok(Receipt {
        message: message.to_owned(),
    })
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
