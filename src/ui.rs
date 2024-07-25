use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/moduloais/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/moduloais/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
