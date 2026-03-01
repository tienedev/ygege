use crate::DOMAIN;
use crate::config::Config;
use crate::rest::client_extractor::MaybeCustomClient;
use actix_web::{HttpRequest, HttpResponse, get, web};
use serde_json::Value;
use tokio::time::{Duration, sleep};

#[get("/torrent/{id:[0-9]+}")]
pub async fn download_torrent(
    data: MaybeCustomClient,
    config: web::Data<Config>,
    req_data: HttpRequest,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let id = req_data.match_info().get("id").unwrap();
    let id = id.parse::<usize>()?;

    let domain_lock = DOMAIN.lock()?;
    let cloned_guard = domain_lock.clone();
    let domain = cloned_guard.as_str();
    drop(domain_lock);

    // Request token
    let url = format!("https://{}/engine/start_download_timer", domain);
    let body = format!("torrent_id={}", id);

    debug!("Request download token {} {}", url, body);

    let response = data.client.post_form(&url, &body).await?;

    debug!("start_download_timer response: status={}, body_len={}, body_preview='{}'",
        response.status,
        response.body.len(),
        &response.body[..response.body.len().min(200)]
    );

    if !(200..300).contains(&response.status) {
        return Err(format!("Failed to get token: {}", response.status).into());
    }

    let json: Value = serde_json::from_str(&response.body)?;
    debug!("Response {}", json);

    let token = json
        .get("token")
        .and_then(|h| h.as_str())
        .ok_or("Token not found in start_download_timer response")?;

    if !config.turbo_enabled.unwrap_or(false) {
        debug!("Wait 30 secs...");
        sleep(Duration::from_secs(30)).await;
        debug!("Wait is over");
    }

    // Request signed torrent file
    let url = format!(
        "https://{}/engine/download_torrent?id={}&token={}",
        domain, id, token
    );
    debug!("download URL {}", url);

    let (status, bytes) = data.client.get_bytes(&url).await?;

    if !(200..300).contains(&status) {
        if status == 302 {
            return match crate::utils::get_remaining_downloads(&data.client).await {
                Ok(0) => {
                    error!("No remaining downloads");
                    Err("No remaining downloads".into())
                }
                Ok(n) => {
                    warn!(
                        "Failed to download torrent, but you have {} remaining downloads, might be caused by an insufficient ratio.",
                        n
                    );
                    Err("Failed to download torrent, but you have remaining downloads.".into())
                }
                Err(e) => {
                    error!("Error while checking remaining downloads: {}", e);
                    Err("Failed to download torrent and check remaining downloads.".into())
                }
            };
        }
        return Err(format!(
            "Failed to get torrent file: {} {}",
            status,
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }

    let mut response_builder = HttpResponse::Ok();
    response_builder
        .content_type("application/x-bittorrent")
        .append_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}.torrent\"", id),
        ));

    if let Some(cookies) = data.cookies_header {
        response_builder.insert_header(("X-Session-Cookies", cookies));
    }

    Ok(response_builder.body(bytes))
}
