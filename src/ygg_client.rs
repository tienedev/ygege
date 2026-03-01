use crate::flaresolverr::FlareSolverr;
use std::sync::Arc;

#[derive(Clone)]
pub enum YggClient {
    Direct(wreq::Client),
    Proxied {
        flaresolverr: Arc<FlareSolverr>,
        session_id: String,
        /// Direct HTTP client with cookies from FlareSolverr session.
        /// Used for API calls (JSON) and binary downloads that FlareSolverr
        /// cannot handle (Chrome wraps JSON in HTML and can't return binary data).
        cookie_client: wreq::Client,
    },
}

pub struct YggResponse {
    pub status: u16,
    pub body: String,
    pub url: String,
}

impl YggClient {
    fn session_ref(session_id: &str) -> Option<&str> {
        if session_id.is_empty() {
            None
        } else {
            Some(session_id)
        }
    }

    /// Extract actual content from FlareSolverr's HTML wrapper.
    /// FlareSolverr returns Chrome's rendered page source, which wraps
    /// JSON API responses in <pre> tags. This extracts the inner content.
    fn strip_html_wrapper(html: &str) -> String {
        if html.trim_start().starts_with('<') {
            if let Some(pre_start) = html.find("<pre") {
                if let Some(gt_pos) = html[pre_start..].find('>') {
                    let content_start = pre_start + gt_pos + 1;
                    if let Some(pre_end) = html[content_start..].find("</pre>") {
                        return html[content_start..content_start + pre_end].to_string();
                    }
                }
            }
        }
        html.to_string()
    }

    pub async fn get(&self, url: &str) -> Result<YggResponse, Box<dyn std::error::Error>> {
        match self {
            YggClient::Direct(client) => {
                let response = client.get(url).send().await?;
                let status = response.status().as_u16();
                let final_url = response.url().to_string();
                let body = response.text().await?;
                Ok(YggResponse {
                    status,
                    body,
                    url: final_url,
                })
            }
            YggClient::Proxied {
                flaresolverr,
                session_id,
                ..
            } => {
                let response = flaresolverr
                    .get(url, Self::session_ref(session_id), None)
                    .await?;
                let solution = response
                    .solution
                    .ok_or("No solution in FlareSolverr response")?;
                Ok(YggResponse {
                    status: solution.status,
                    body: solution.response,
                    url: solution.url,
                })
            }
        }
    }

    pub async fn post_form(
        &self,
        url: &str,
        form_data: &str,
    ) -> Result<YggResponse, Box<dyn std::error::Error>> {
        match self {
            YggClient::Direct(client) => {
                let response = client
                    .post(url)
                    .body(form_data.to_string())
                    .header(
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    )
                    .send()
                    .await?;
                let status = response.status().as_u16();
                let final_url = response.url().to_string();
                let body = response.text().await?;
                Ok(YggResponse {
                    status,
                    body,
                    url: final_url,
                })
            }
            YggClient::Proxied {
                cookie_client,
                ..
            } => {
                // Use the direct cookie_client for POST form requests (e.g. start_download_timer).
                // FlareSolverr wraps JSON API responses in Chrome's HTML viewer, so
                // direct HTTP with session cookies gives us the raw JSON response.
                debug!("post_form: using direct cookie_client for API call");
                let response = cookie_client
                    .post(url)
                    .body(form_data.to_string())
                    .header(
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    )
                    .send()
                    .await?;
                let status = response.status().as_u16();
                let final_url = response.url().to_string();
                let body = response.text().await?;
                Ok(YggResponse {
                    status,
                    body,
                    url: final_url,
                })
            }
        }
    }

    pub async fn get_bytes(&self, url: &str) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error>> {
        match self {
            YggClient::Direct(client) => {
                let response = client.get(url).send().await?;
                let status = response.status().as_u16();
                let bytes = response.bytes().await?.to_vec();
                Ok((status, bytes))
            }
            YggClient::Proxied {
                cookie_client,
                ..
            } => {
                // FlareSolverr cannot return binary data (Chrome renders pages as HTML).
                // Use the direct HTTP client with cookies from the FlareSolverr session
                // to download binary files like .torrent.
                debug!("get_bytes: using direct cookie_client for binary download");
                let response = cookie_client.get(url).send().await?;
                let status = response.status().as_u16();
                let bytes = response.bytes().await?.to_vec();
                Ok((status, bytes))
            }
        }
    }

    pub fn as_wreq_client(&self) -> Option<&wreq::Client> {
        match self {
            YggClient::Direct(client) => Some(client),
            YggClient::Proxied { .. } => None,
        }
    }
}
