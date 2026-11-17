//! Engine tests. They read the real registry (privacy settings) but never
//! write to it; browsers, apps and data folders are temporary.

use super::*;
use ga_ipc::Request;
use ga_scanners::apps::AppRoots;
use ga_scanners::browsers::BrowserRoots;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

struct Setup {
    _tmp: tempfile::TempDir,
    engine: Arc<Engine>,
    slot: Arc<UserSlot>,
    data_dir: std::path::PathBuf,
}

async fn setup() -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let engine = Engine::start(EngineConfig {
        data_root: tmp.path().join("data"),
        proxy_port: 0,
        network_monitor: false,
        app_scan: false,
        dns_blocking: false,
    })
    .await;
    let data_dir = tmp.path().join("data").join("users").join("test");
    let ctx = UserContext {
        key: "test".into(),
        sid: None,
        use_user_hive: false,
        browser_roots: BrowserRoots {
            local_app_data: Some(tmp.path().join("Local")),
            app_data: Some(tmp.path().join("Roaming")),
        },
        app_roots: AppRoots::default(),
        data_dir: data_dir.clone(),
    };
    let slot = engine.slot(&ctx);
    Setup {
        _tmp: tmp,
        engine,
        slot,
        data_dir,
    }
}

async fn call(s: &Setup, req: Request) -> Result<Value, String> {
    s.engine.handle(s.slot.clone(), req).await
}

async fn overview_when_scanned(s: &Setup) -> Value {
    for _ in 0..100 {
        let o = call(s, Request::Overview).await.unwrap();
        if !o["scanning"].as_bool().unwrap() && !o["generated_unix"].is_null() {
            return o;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("scan did not finish");
}

#[tokio::test(flavor = "multi_thread")]
async fn first_overview_scans_and_saves_a_baseline() {
    let s = setup().await;
    let o = overview_when_scanned(&s).await;
    assert!(o["privacy"]["settings"].as_array().unwrap().len() >= 10);
    assert_eq!(o["cookies"]["total_cookies"], 0);
    assert!(o["score"]["value"].as_u64().unwrap() <= 100);
    assert!(o["apps"].is_null(), "app scan is off in tests");
    assert!(s.data_dir.join("baseline.json").is_file());
    // First scan only records a baseline: nothing to compare with yet.
    assert_eq!(o["unread_alerts"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_scan_runs_at_a_time() {
    let s = setup().await;
    let first = call(&s, Request::ScanNow).await.unwrap();
    let second = call(&s, Request::ScanNow).await.unwrap();
    assert_eq!(first["started"], true);
    assert_eq!(second["started"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn fixes_and_changes_are_read_only_views() {
    let s = setup().await;
    let fixes = call(&s, Request::Fixes).await.unwrap();
    for f in fixes.as_array().unwrap() {
        assert!(f["fix"].is_string() && f["writes"].is_array(), "{f}");
    }
    assert_eq!(call(&s, Request::Changes).await.unwrap(), serde_json::json!([]));
    let err = call(&s, Request::ApplyFix { setting_id: "nope".into() }).await.unwrap_err();
    assert!(err.contains("unknown setting"));
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_is_controlled_through_the_engine() {
    let s = setup().await;
    let status = call(&s, Request::ProxyStatus).await.unwrap();
    assert!(status["listening"].is_string(), "{status}");
    assert_eq!(status["inspected_apps"], serde_json::json!([]));

    let status = call(&s, Request::ProxySetApps { apps: vec!["Discord.exe".into()] }).await.unwrap();
    assert_eq!(status["inspected_apps"], serde_json::json!(["discord.exe"]));

    let ca = call(&s, Request::ProxyExportCa).await.unwrap();
    assert!(ca["pem"].as_str().unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(std::path::Path::new(ca["path"].as_str().unwrap()).is_file());
    assert_eq!(call(&s, Request::ProxyEvents).await.unwrap(), serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reports_components() {
    let s = setup().await;
    let st = call(&s, Request::Status).await.unwrap();
    assert_eq!(st["network"]["state"], "off");
    assert_eq!(st["users"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn running_apps_lists_own_programs_but_not_windows() {
    let s = setup().await;
    let apps = call(&s, Request::RunningApps).await.unwrap();
    let apps = apps.as_array().unwrap();
    // The test binary itself is one of this user's programs.
    let me = std::env::current_exe().unwrap();
    let me = me.file_name().unwrap().to_string_lossy().to_lowercase();
    assert!(apps.iter().any(|a| a["exe"].as_str().unwrap().to_lowercase() == me), "{apps:?}");
    let windows = std::env::var("SystemRoot").unwrap().to_lowercase();
    assert!(apps.iter().all(|a| !a["path"].as_str().unwrap().to_lowercase().starts_with(&windows)));
}
