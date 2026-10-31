//! Typed request-boundary failures. HTTP rendering remains in the proxy adapter.

use axum::http::StatusCode;

/// A failure after the request has passed authentication/body validation, or while routing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RequestError {
    NoEdge,
    ModelNotFound,
    AtCapacity,
    BadGateway(String),
    UpstreamStatus(StatusCode, String),
    TunnelRead(String),
    HeadTimeout,
}

impl RequestError {
    pub(super) fn status(&self) -> StatusCode {
        match self {
            Self::NoEdge => StatusCode::SERVICE_UNAVAILABLE,
            Self::ModelNotFound => StatusCode::NOT_FOUND,
            Self::AtCapacity => StatusCode::TOO_MANY_REQUESTS,
            Self::BadGateway(_) | Self::TunnelRead(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamStatus(status, _) => *status,
            Self::HeadTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    pub(super) fn message(&self) -> String {
        match self {
            Self::NoEdge => "no edge available".into(),
            Self::ModelNotFound => "model not found on any agent".into(),
            Self::AtCapacity => "agent at capacity".into(),
            Self::BadGateway(message) | Self::TunnelRead(message) => message.clone(),
            Self::UpstreamStatus(_, message) => message.clone(),
            Self::HeadTimeout => "upstream timed out".into(),
        }
    }
}

/// Compatibility name used by the existing routing/head split.
pub(super) type RouteFailure = RequestError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_error_mapping_is_stable() {
        let cases = [
            (
                RequestError::NoEdge,
                StatusCode::SERVICE_UNAVAILABLE,
                "no edge available",
            ),
            (
                RequestError::ModelNotFound,
                StatusCode::NOT_FOUND,
                "model not found on any agent",
            ),
            (
                RequestError::AtCapacity,
                StatusCode::TOO_MANY_REQUESTS,
                "agent at capacity",
            ),
            (
                RequestError::BadGateway("bad".into()),
                StatusCode::BAD_GATEWAY,
                "bad",
            ),
            (
                RequestError::TunnelRead("read".into()),
                StatusCode::BAD_GATEWAY,
                "read",
            ),
            (
                RequestError::UpstreamStatus(StatusCode::BAD_GATEWAY, "upstream".into()),
                StatusCode::BAD_GATEWAY,
                "upstream",
            ),
            (
                RequestError::HeadTimeout,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream timed out",
            ),
        ];
        for (error, status, message) in cases {
            assert_eq!(error.status(), status);
            assert_eq!(error.message(), message);
        }
    }
}
