//! Decodes tracker requests into plain language (FR-16).
//!
//! Input is an HTTP request as a browser extension, a decrypting proxy or a
//! HAR file sees it. Output says which company received which kinds of data.
//! Unknown parameters are left out rather than guessed at.

pub mod consent;
mod generic;
mod google;
pub mod har;
mod meta;
mod microsoft;
mod params;
mod segment;
mod tiktok;

use ga_core::DecodedPayload;
use params::Parsed;

/// An HTTP request as observed before encryption.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    /// Request body as text (form-encoded, JSON or newline-separated).
    pub body: Option<&'a str>,
}

type Decoder = fn(&Parsed) -> Option<Vec<DecodedPayload>>;

const DECODERS: &[Decoder] = &[
    google::ga4,
    google::universal_analytics,
    meta::pixel,
    microsoft::bing_uet,
    microsoft::linkedin_insight,
    segment::segment,
    tiktok::pixel,
];

/// Decodes a request. Empty when it is not a recognised tracker request.
/// One request can carry several hits (batched analytics events).
pub fn decode(request: &Request<'_>) -> Vec<DecodedPayload> {
    let Some(parsed) = Parsed::new(request) else { return Vec::new() };
    DECODERS
        .iter()
        .find_map(|d| d(&parsed))
        .unwrap_or_default()
}

pub use generic::summarize;

/// Privacy choices carried in a request (consent strings and similar).
pub fn consent_signals(request: &Request<'_>) -> Vec<ga_core::ConsentSignal> {
    consent::signals(request)
}

/// Products this crate can decode, for "what we understand" in the UI.
pub const SUPPORTED: &[&str] = &[
    "Google Analytics 4",
    "Google Universal Analytics",
    "Meta Pixel",
    "Microsoft Advertising (Bing UET)",
    "LinkedIn Insight Tag",
    "Twilio Segment",
    "TikTok Pixel",
];

#[cfg(test)]
mod tests;
