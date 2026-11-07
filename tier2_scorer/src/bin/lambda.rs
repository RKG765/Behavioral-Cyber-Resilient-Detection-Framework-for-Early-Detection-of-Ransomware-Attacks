//! AWS Lambda (Function URL behind CloudFront): POST /v1/score {"features": [99 numbers]}
//! -> {"verdict": "KILL" | "BENIGN", "request_id": ...}. No auth yet (build step 2).

use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};
use serde::Deserialize;
use serde_json::json;
use tier2_scorer::{score, verdict, FEATURE_DIM};

#[derive(Deserialize)]
struct ScoreRequest {
    features: Vec<f32>,
}

fn reply(status: u16, body: serde_json::Value) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string().into())?)
}

async fn handler(req: Request) -> Result<Response<Body>, Error> {
    if req.method() != "POST" || req.uri().path() != "/v1/score" {
        return reply(404, json!({ "error": "not found" }));
    }
    let features = match serde_json::from_slice::<ScoreRequest>(req.body()) {
        Ok(r) if r.features.len() == FEATURE_DIM && r.features.iter().all(|f| f.is_finite()) => r.features,
        _ => return reply(400, json!({ "error": "body must be {\"features\": [99 finite numbers]}" })),
    };
    let x: [f32; FEATURE_DIM] = features.try_into().unwrap();
    let request_id = req.lambda_context_ref().map(|c| c.request_id.clone()).unwrap_or_default();
    reply(200, json!({ "verdict": verdict(score(&x)), "request_id": request_id }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(path: &str, body: String) -> Request {
        let mut r = Request::new(Body::from(body));
        *r.method_mut() = lambda_http::http::Method::POST;
        *r.uri_mut() = path.parse().unwrap();
        r
    }

    fn features(n: usize) -> String {
        format!("{{\"features\":[{}]}}", vec!["0.5"; n].join(","))
    }

    #[tokio::test]
    async fn validates_then_scores() {
        assert_eq!(handler(post("/v1/score", "not json".into())).await.unwrap().status(), 400);
        assert_eq!(handler(post("/v1/score", features(98))).await.unwrap().status(), 400);
        assert_eq!(handler(post("/other", features(99))).await.unwrap().status(), 404);
        let ok = handler(post("/v1/score", features(99))).await.unwrap();
        assert_eq!(ok.status(), 200);
        assert!(std::str::from_utf8(ok.body()).unwrap().contains("\"verdict\""));
    }
}
