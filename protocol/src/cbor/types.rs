use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct TimeValue(
    #[serde(with = "ts_milliseconds")] pub DateTime<Utc>,
    pub f32,
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CustomMetric {
    pub typ: String,
    pub values: Vec<TimeValue>,
}
