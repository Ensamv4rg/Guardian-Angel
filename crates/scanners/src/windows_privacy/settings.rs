//! Interprets Windows privacy registry values (requirement FR-3).
//!
//! Every key here was checked against a real Windows 10 22H2 machine. When a
//! value is missing, the state is only reported as a Windows default where
//! that default is well established; otherwise it is `Exposure::Unknown`.

use super::registry::{Hive, Registry};
use ga_core::{Exposure, PrivacyArea, PrivacySetting};

const DATA_COLLECTION_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
const DATA_COLLECTION: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection";
const ADVERTISING_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo";
const ADVERTISING: &str = r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo";
const PRIVACY: &str = r"Software\Microsoft\Windows\CurrentVersion\Privacy";
const EXPLORER_ADVANCED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const USER_PROFILE: &str = r"Control Panel\International\User Profile";
const INPUT_PERSONALIZATION: &str = r"Software\Microsoft\InputPersonalization";
const INPUT_TIPC: &str = r"Software\Microsoft\Input\TIPC";
const ONLINE_SPEECH: &str = r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy";
const CONTENT_DELIVERY: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
pub(super) const CONSENT_STORE: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

pub fn read_settings(reg: &dyn Registry) -> Vec<PrivacySetting> {
    let mut settings = vec![diagnostic_data(reg), advertising_id(reg), location(reg)];
    settings.extend(TOGGLES.iter().map(|t| t.read(reg)));
    settings
}

fn source(hive: Hive, path: &str, name: &str) -> String {
    format!(r"{}\{}\{}", hive.prefix(), path, name)
}

fn diagnostic_data(reg: &dyn Registry) -> PrivacySetting {
    let policy = reg.dword(Hive::LocalMachine, DATA_COLLECTION_POLICY, "AllowTelemetry");
    let (value, set_by_policy, path) = match policy {
        Some(v) => (Some(v), true, DATA_COLLECTION_POLICY),
        None => (
            reg.dword(Hive::LocalMachine, DATA_COLLECTION, "AllowTelemetry"),
            false,
            DATA_COLLECTION,
        ),
    };
    let (state, exposure) = match value {
        Some(0) => ("Security (off)".to_owned(), Exposure::Protected),
        Some(1) => ("Required (minimum)".to_owned(), Exposure::Protected),
        Some(2) => ("Enhanced".to_owned(), Exposure::Exposed),
        Some(3) => ("Optional (full)".to_owned(), Exposure::Exposed),
        Some(v) => (format!("Unrecognised value {v}"), Exposure::Unknown),
        None => ("Not set".to_owned(), Exposure::Unknown),
    };
    PrivacySetting {
        id: "diagnostic_data",
        area: PrivacyArea::Diagnostics,
        title: "Diagnostic data sent to Microsoft",
        state,
        exposure,
        explanation: "How much usage data Windows sends to Microsoft. Optional includes \
            websites you visit in Microsoft Edge and detailed app and feature use; \
            Required is the minimum Windows allows on Home and Pro.",
        set_by_policy,
        source: source(Hive::LocalMachine, path, "AllowTelemetry"),
    }
}

fn advertising_id(reg: &dyn Registry) -> PrivacySetting {
    let explanation = "A unique ID that apps can read to show you personalised ads \
        and connect your activity across apps.";
    if reg.dword(Hive::LocalMachine, ADVERTISING_POLICY, "DisabledByGroupPolicy") == Some(1) {
        return PrivacySetting {
            id: "advertising_id",
            area: PrivacyArea::Advertising,
            title: "Advertising ID",
            state: "Off".to_owned(),
            exposure: Exposure::Protected,
            explanation,
            set_by_policy: true,
            source: source(Hive::LocalMachine, ADVERTISING_POLICY, "DisabledByGroupPolicy"),
        };
    }
    let (state, exposure) = match reg.dword(Hive::CurrentUser, ADVERTISING, "Enabled") {
        Some(0) => ("Off", Exposure::Protected),
        Some(_) => ("On", Exposure::Exposed),
        None => ("Not set", Exposure::Unknown),
    };
    PrivacySetting {
        id: "advertising_id",
        area: PrivacyArea::Advertising,
        title: "Advertising ID",
        state: state.to_owned(),
        exposure,
        explanation,
        set_by_policy: false,
        source: source(Hive::CurrentUser, ADVERTISING, "Enabled"),
    }
}

/// Location has a device-wide switch (HKLM) and a per-account switch (HKCU);
/// either one set to "Deny" turns it off.
fn location(reg: &dyn Registry) -> PrivacySetting {
    let path = format!(r"{CONSENT_STORE}\location");
    let device = reg.string(Hive::LocalMachine, &path, "Value");
    let user = reg.string(Hive::CurrentUser, &path, "Value");
    let denied = |v: &Option<String>| v.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("Deny"));
    let allowed = |v: &Option<String>| v.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("Allow"));

    let (state, exposure) = if denied(&device) {
        ("Off for this device", Exposure::Protected)
    } else if denied(&user) {
        ("Off for your account", Exposure::Protected)
    } else if allowed(&device) && allowed(&user) {
        ("On", Exposure::Exposed)
    } else {
        ("Not set", Exposure::Unknown)
    };
    PrivacySetting {
        id: "location",
        area: PrivacyArea::Location,
        title: "Location services",
        state: state.to_owned(),
        exposure,
        explanation: "Lets Windows and apps use your device's location. \
            See the app list for which apps used it and when.",
        set_by_policy: false,
        source: source(Hive::CurrentUser, &path, "Value"),
    }
}

/// What to report when a toggle's value is missing.
#[derive(Clone, Copy)]
enum WhenMissing {
    /// Windows treats a missing value as on.
    DefaultOn,
    /// Windows treats a missing value as off.
    DefaultOff,
    /// The default varies by edition, version or setup choices.
    Unknown,
}

/// A simple on/off DWORD setting where "on" means data is collected or shared.
struct Toggle {
    id: &'static str,
    area: PrivacyArea,
    title: &'static str,
    explanation: &'static str,
    path: &'static str,
    name: &'static str,
    /// The value that means the feature is on. Opt-out flags use 0.
    on_value: u32,
    when_missing: WhenMissing,
}

impl Toggle {
    fn read(&self, reg: &dyn Registry) -> PrivacySetting {
        let (state, exposure) = match reg.dword(Hive::CurrentUser, self.path, self.name) {
            Some(v) if v == self.on_value => ("On", Exposure::Exposed),
            Some(_) => ("Off", Exposure::Protected),
            None => match self.when_missing {
                WhenMissing::DefaultOn => ("On (Windows default)", Exposure::Exposed),
                WhenMissing::DefaultOff => ("Off (never turned on)", Exposure::Protected),
                WhenMissing::Unknown => ("Not set", Exposure::Unknown),
            },
        };
        PrivacySetting {
            id: self.id,
            area: self.area,
            title: self.title,
            state: state.to_owned(),
            exposure,
            explanation: self.explanation,
            set_by_policy: false,
            source: source(Hive::CurrentUser, self.path, self.name),
        }
    }
}

const TOGGLES: &[Toggle] = &[
    Toggle {
        id: "tailored_experiences",
        area: PrivacyArea::Diagnostics,
        title: "Tailored experiences",
        explanation: "Lets Microsoft use your diagnostic data to show you personalised \
            tips, ads and recommendations.",
        path: PRIVACY,
        name: "TailoredExperiencesWithDiagnosticDataEnabled",
        on_value: 1,
        when_missing: WhenMissing::Unknown,
    },
    Toggle {
        id: "language_list",
        area: PrivacyArea::Advertising,
        title: "Websites can read your language list",
        explanation: "Lets websites read the languages you have installed, which helps \
            them recognise and fingerprint you.",
        path: USER_PROFILE,
        name: "HttpAcceptLanguageOptOut",
        on_value: 0,
        when_missing: WhenMissing::DefaultOn,
    },
    Toggle {
        id: "app_launch_tracking",
        area: PrivacyArea::ActivityTracking,
        title: "Track which apps you open",
        explanation: "Windows records which apps you launch to personalise Start and search.",
        path: EXPLORER_ADVANCED,
        name: "Start_TrackProgs",
        on_value: 1,
        when_missing: WhenMissing::DefaultOn,
    },
    Toggle {
        id: "typing_personalization",
        area: PrivacyArea::InputAndSpeech,
        title: "Typing and handwriting history",
        explanation: "Windows collects what you type and write by hand to build a \
            personal dictionary.",
        path: INPUT_PERSONALIZATION,
        name: "RestrictImplicitTextCollection",
        on_value: 0,
        when_missing: WhenMissing::Unknown,
    },
    Toggle {
        id: "improve_inking_typing",
        area: PrivacyArea::InputAndSpeech,
        title: "Send typing and inking data to Microsoft",
        explanation: "Sends samples of your typing and handwriting to Microsoft to \
            improve its recognition.",
        path: INPUT_TIPC,
        name: "Enabled",
        on_value: 1,
        when_missing: WhenMissing::Unknown,
    },
    Toggle {
        id: "online_speech",
        area: PrivacyArea::InputAndSpeech,
        title: "Online speech recognition",
        explanation: "Sends your voice to Microsoft's cloud speech service when you \
            dictate or use voice features.",
        path: ONLINE_SPEECH,
        name: "HasAccepted",
        on_value: 1,
        when_missing: WhenMissing::DefaultOff,
    },
    Toggle {
        id: "silent_app_installs",
        area: PrivacyArea::Suggestions,
        title: "Automatic installs of suggested apps",
        explanation: "Lets Windows install suggested and sponsored apps without asking you.",
        path: CONTENT_DELIVERY,
        name: "SilentInstalledAppsEnabled",
        on_value: 1,
        when_missing: WhenMissing::Unknown,
    },
    Toggle {
        id: "start_suggestions",
        area: PrivacyArea::Suggestions,
        title: "Suggested apps in Start",
        explanation: "Shows suggested apps, which can be paid promotions, in the Start menu.",
        path: CONTENT_DELIVERY,
        name: "SystemPaneSuggestionsEnabled",
        on_value: 1,
        when_missing: WhenMissing::Unknown,
    },
];
