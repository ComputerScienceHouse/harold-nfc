extern crate reqwest;
extern crate gatekeeper_members;
extern crate libgatekeeper_sys;
extern crate chrono;

use gatekeeper_members::{GateKeeperMemberListener, FetchError};
use libgatekeeper_sys::Nfc;
use std::process::{Command, ExitStatus};
use reqwest::StatusCode;
use serde_json::json;
use std::env;
use chrono::prelude::*;

fn get_volume() -> &'static str {
    let now = Local::now();
    let hour = now.hour();
    let weekday = now.weekday();

    if weekday == Weekday::Sun {
        if (hour < 1 || hour >= 7) && 23 >= hour {
            return "100";
        }
    } else if weekday == Weekday::Sat {
        if hour < 1 || hour >= 7 {
            return "100";
        }
    } else {
        if 23 >= hour && hour >= 7 {
            return "100";
        }
    }

    return "73";
}

fn play_music(path: &str, do_cap: bool) -> Result<&str, ExitStatus> {
    let mut cmd = &mut Command::new("ffplay");
    cmd = cmd
        .arg(path.clone()).arg("-b:a").arg("64k")
        .arg("-nodisp").arg("-autoexit")
        .arg("-volume").arg(get_volume())
        .arg("-loglevel").arg("error");
    if do_cap {
        cmd = cmd.arg("-t").arg("30");
    }
    println!("Playing audio {}", path);
    let mut child = cmd.spawn().unwrap();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited
                if status.success() {
                    return Ok(path.clone());
                } else {
                    return Err(status);
                }
            },
            Ok(None) => {
                // TODO: Dammit here
            },
            Err(e) => println!("Error waiting?? {:?}", e),
        }
    }
}

fn scan_complete(uid: &str) -> &'static str {
    match uid {
        "mom" => {
            return "aaa.mp3";
        },
        _ => {
            return "scan-complete-mom.mp3";
        }
    }
}

fn get_audiophiler(http: reqwest::blocking::Client, harold_auth: &str, uid: String) -> Option<String> {
    let response = http.post(
        "https://audiophiler.csh.rit.edu/get_harold/".to_string() + &uid
    ).json(&json!({
        "auth_key": harold_auth
    })).send();
    match response {
        Ok(res) => match res.status() {
            StatusCode::OK => return Some(res.text().unwrap()),
            status => {
                println!("Audiophiler responded non-200: {:?}", status);
                return None;
            },
        },
        Err(err) => {
            println!("Couldn't fetch harold for user: {:?}", err);
            return None;
        },
    };
}

fn run_harold(http: reqwest::blocking::Client, harold_auth: String, uid: String) {
    // Hopefully we don't crash? lol
    play_music(scan_complete(&uid.clone()), false).unwrap();
    println!("Played scan complete");
    if let Some(sound) = get_audiophiler(http, &harold_auth, uid.clone()) {
        play_music(&sound, true).unwrap();
    } else {
        println!("Couldn't fetch Harold for user {}?", uid);
    }
}

fn main() {
    let mut nfc = Nfc::new().unwrap();
    let mut listener = GateKeeperMemberListener::new(
        &mut nfc,
        env::var("HAROLD_GK_READER").unwrap_or(
            "pn532_uart:/dev/ttyUSB0".to_string()
        ).to_string()
    ).unwrap();
    let http = reqwest::blocking::Client::new();

    let harold_auth = env::var("HAROLD_AUTH").unwrap().to_string();

    loop {
        if let Some(association) = listener.wait_for_user() {
            // Fetch user!
            println!("Read {}", association);
            match listener.fetch_user(association) {
                Ok(value) => {
                    println!("Got user with name {}", value["user"]["uid"].as_str().unwrap());
                    run_harold(
                        http.clone(),
                        harold_auth.clone(),
                        value["user"]["uid"].as_str().unwrap().to_string()
                    );
                }
                Err(FetchError::NotFound) => {
                    println!("User not found");
                }
                Err(_) => {
                    println!("Failed fetching...");
                }
            };
        }
    }
}
