mod page;
mod util;

use axum::{
    error_handling::HandleErrorLayer,
    extract::Form,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    BoxError, Router,
};
use serde::Deserialize;
use std::time::Duration;
use tower::{buffer::BufferLayer, limit::RateLimitLayer, ServiceBuilder};
use util::{decrypt_ecb, encrypt_ecb, SECRET_KEY};

#[derive(Deserialize)]
struct EncodeRequest {
    secret_key: String,
    content: String,
}

#[derive(Deserialize)]
struct DecodeRequest {
    secret_key: String,
    qr_data: String,
}

async fn index() -> Html<&'static str> {
    Html(page::INDEX)
}

async fn get_encode() -> Html<&'static str> {
    Html(page::ENCODE)
}

async fn get_decode() -> Html<&'static str> {
    Html(page::DECODE)
}

async fn post_encode(Form(data): Form<EncodeRequest>) -> String {
    let sk = &data.secret_key;

    if sk != SECRET_KEY {
        return String::from("Invalid secret key");
    }

    match encrypt_ecb(&data.content) {
        Ok(v) => v,
        Err(_) => String::from("Internal server error"),
    }
}

async fn post_decode(Form(data): Form<DecodeRequest>) -> String {
    let sk = &data.secret_key;

    if sk != SECRET_KEY {
        return String::from("Invalid secret key");
    }

    match decrypt_ecb(&data.qr_data) {
        Ok(v) => v,
        Err(_) => String::from("Internal server error"),
    }
}

#[shuttle_runtime::main]
async fn main() -> shuttle_axum::ShuttleAxum {
    let router = Router::new()
        .route("/", get(index))
        .route("/encode", get(get_encode))
        .route("/encode", post(post_encode))
        .route("/decode", get(get_decode))
        .route("/decode", post(post_decode))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|err: BoxError| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled error: {}", err),
                    )
                }))
                .layer(BufferLayer::new(1024))
                // 3 req/s cuz why not
                .layer(RateLimitLayer::new(3, Duration::from_secs(1))),
        );

    Ok(router.into())
}
