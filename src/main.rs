use chrono::prelude::*;
use gatekeeper_members::{FetchError, GateKeeperMemberListener, RealmType};
use rand::prelude::SliceRandom;
use reqwest::StatusCode;
use serde_json::json;
use std::env;
use std::process::{Command, ExitStatus};
use std::time::Duration;

fn get_volume() -> &'static str {
    let now = Local::now();
    let hour = now.hour();
    let weekday = now.weekday();

    if weekday == Weekday::Sun {
        if !(1..7).contains(&hour) && 23 >= hour {
            return "100";
        }
    } else if weekday == Weekday::Sat {
        if !(1..7).contains(&hour) {
            return "100";
        }
    } else if (7..=23).contains(&hour) {
        return "100";
    }

    "73"
}

fn play_music(path: &str, do_cap: bool) -> Result<(), ExitStatus> {
    let mut cmd = &mut Command::new("ffplay");
    cmd = cmd
        .arg(path)
        .arg("-b:a")
        .arg("64k")
        .arg("-nodisp")
        .arg("-autoexit")
        .arg("-volume")
        .arg(get_volume())
        .arg("-loglevel")
        .arg("error");
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
                    return Ok(());
                } else {
                    return Err(status);
                }
            }
            Ok(None) => {
                // TODO: Dammit here
            }
            Err(e) => println!("Error waiting?? {:?}", e),
        }
    }
}

fn scan_complete(uid: &str) -> String {
    match uid {
        "mom" => "special/aaa.mp3".to_string(),
        _ => {
            // get all files from scans folder
            let files = std::fs::read_dir("scans").unwrap();
            // return a random file
            let mut rng = rand::thread_rng();
            let file_list: Vec<_> = files.map(|f| f.unwrap().path()).collect();
            let file = &file_list.choose(&mut rng).unwrap();
            return file.to_str().unwrap().to_string();
        }
    }
}

fn get_audiophiler(
    http: reqwest::blocking::Client,
    harold_auth: &str,
    uid: String,
) -> Result<String, RequestError> {
    let response = http
        .post("https://audiophiler.csh.rit.edu/get_harold/".to_string() + &uid)
        .json(&json!({ "auth_key": harold_auth }))
        .send();
    match response {
        Ok(res) => match res.status() {
            StatusCode::OK => Ok(res.text().unwrap()),
            status => {
                println!("Audiophiler responded non-200: {:?}", status);
                Err(RequestError::StatusCode(status))
            }
        },
        Err(err) => {
            println!("Couldn't fetch harold for user: {:?}", err);
            Err(RequestError::Unknown)
        }
    }
}

enum RequestError {
    Unknown,
    StatusCode(StatusCode),
}

enum RunFailure {
    ExitCode(ExitStatus),
    RequestError(RequestError),
}

fn run_harold(
    http: reqwest::blocking::Client,
    harold_auth: String,
    uid: String,
) -> Result<(), RunFailure> {
    // Hopefully we don't crash? lol
    if let Err(err) = play_music(&scan_complete(&uid), false) {
        return Err(RunFailure::ExitCode(err));
    }
    println!("Played scan complete");
    match get_audiophiler(http, &harold_auth, uid) {
        Ok(sound) => match play_music(&sound, true) {
            Ok(_) => Ok(()),
            Err(err) => Err(RunFailure::ExitCode(err)),
        },
        Err(request_error) => Err(RunFailure::RequestError(request_error)),
    }
}

fn main() {
    env_logger::init();
    let mut listener = GateKeeperMemberListener::new(
        env::var("HAROLD_GK_READER").unwrap_or_else(|_| "pn532_uart:/dev/ttyUSB0".to_string()),
        RealmType::MemberProjects,
    )
    .unwrap();
    let http = reqwest::blocking::Client::new();

    let harold_auth = env::var("HAROLD_AUTH").unwrap();

    loop {
        if let Some(association) = listener.wait_for_user() {
            // Fetch user!
            println!("Read {}", association);
            match listener.fetch_user(association) {
                Ok(value) => {
                    println!(
                        "Got user with name {}",
                        value["user"]["uid"].as_str().unwrap()
                    );
                    match run_harold(
                        http.clone(),
                        harold_auth.clone(),
                        value["user"]["uid"].as_str().unwrap().to_string(),
                    ) {
                        Ok(_) => println!("Played harold for user!"),
                        Err(RunFailure::ExitCode(status)) => {
                            eprintln!("Failed to play! {}", status)
                        }
                        Err(RunFailure::RequestError(RequestError::StatusCode(response_code))) => {
                            eprintln!(
                                "Couldn't get user's harold! Server responded with {}",
                                response_code
                            )
                        }
                        Err(RunFailure::RequestError(RequestError::Unknown)) => {
                            eprintln!("Couldn't get user's harold, not sure why!");
                        }
                    }
                }
                Err(FetchError::NotFound) => {
                    println!("User not found");
                }
                Err(_) => {
                    println!("Failed fetching...");
                }
            };
        }
        std::thread::sleep(Duration::from_millis(200)); // Don't spam the reader
    }
}
