use boringhyper::ChromeHeadersExt;
use hyper::{Body, Request};

#[tokio::test]
async fn test_cf_visit() {
    const ENTERPRISE_CF_URL: &str = "https://www.canva.com/pl_pl/";

    let client = boringhyper::create_client();
    let req = Request::builder()
        .uri(ENTERPRISE_CF_URL)
        .with_chrome_headers()
        .body(Body::empty())
        .unwrap();
    let resp = client.request(req).await.expect("Could not do request!");
    assert_eq!(resp.status(), 200);
}
