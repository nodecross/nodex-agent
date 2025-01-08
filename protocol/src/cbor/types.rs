use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Debug)]
pub struct TimeValue(
    #[serde(with = "ts_milliseconds")] pub DateTime<Utc>,
    pub f32,
);

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct CustomMetric {
    #[validate(length(min = 1))]
    pub key: String,
    pub values: Vec<TimeValue>,
}
