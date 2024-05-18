use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result};
use std::sync::Mutex;
use sysinfo::{Networks, System};

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct Metric {
    pub metric_type: MetricType,
    pub value: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Deserialize)]
pub enum MetricType {
    CpuUsage,
    MemoryUsage,
    NetworkReceivedBytes,
    NetworkTransmittedBytes,
    NetworkReceivedPackets,
    NetworkTransmittedPackets,
    DiskReadBytes,
    DiskWrittenBytes,
}

impl Display for MetricType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            MetricType::CpuUsage => write!(f, "cpu_usage"),
            MetricType::MemoryUsage => write!(f, "memory_usage"),
            MetricType::NetworkReceivedBytes => write!(f, "network_received_bytes"),
            MetricType::NetworkTransmittedBytes => write!(f, "network_transmitted_bytes"),
            MetricType::NetworkReceivedPackets => write!(f, "network_received_packets"),
            MetricType::NetworkTransmittedPackets => write!(f, "network_transmitted_packets"),
            MetricType::DiskReadBytes => write!(f, "disk_read_bytes"),
            MetricType::DiskWrittenBytes => write!(f, "disk_written_bytes"),
        }
    }
}

pub trait MetricCollectRepository {
    fn collect(&mut self) -> Vec<Metric>;
}

pub struct MetricCollectRepositoryImpl {
    system: System,
    networks: Networks,
}

impl MetricCollectRepositoryImpl {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            networks: Networks::new(),
        }
    }

    fn cpu_usage(&mut self) -> Metric {
        self.system.refresh_cpu_usage();
        Metric {
            metric_type: MetricType::CpuUsage,
            value: self.system.global_cpu_info().cpu_usage(),
            timestamp: Utc::now(),
        }
    }

    fn memory_usage(&mut self) -> Metric {
        self.system.refresh_memory();
        Metric {
            metric_type: MetricType::MemoryUsage,
            value: self.system.used_memory() as f32,
            timestamp: Utc::now(),
        }
    }

    fn network_info(&mut self) -> Vec<Metric> {
        let mut received_bytes = 0;
        let mut transmitted_bytes = 0;
        let mut received_packets = 0;
        let mut transmitted_packets = 0;

        self.networks.refresh_list();
        for network in self.networks.list().values() {
            received_bytes += network.received();
            transmitted_bytes += network.transmitted();
            received_packets += network.packets_received();
            transmitted_packets += network.packets_transmitted();
        }

        let timestamp = Utc::now();
        vec![
            Metric {
                metric_type: MetricType::NetworkReceivedBytes,
                value: received_bytes as f32,
                timestamp,
            },
            Metric {
                metric_type: MetricType::NetworkTransmittedBytes,
                value: transmitted_bytes as f32,
                timestamp,
            },
            Metric {
                metric_type: MetricType::NetworkReceivedPackets,
                value: received_packets as f32,
                timestamp,
            },
            Metric {
                metric_type: MetricType::NetworkTransmittedPackets,
                value: transmitted_packets as f32,
                timestamp,
            },
        ]
    }

    fn disk_info(&mut self) -> Vec<Metric> {
        let mut read_bytes = 0;
        let mut written_bytes = 0;

        self.system.refresh_processes();
        for process in self.system.processes().values() {
            let disk_usage = process.disk_usage();
            read_bytes += disk_usage.read_bytes;
            written_bytes += disk_usage.written_bytes;
        }

        let timestamp = Utc::now();
        vec![
            Metric {
                metric_type: MetricType::DiskReadBytes,
                value: read_bytes as f32,
                timestamp,
            },
            Metric {
                metric_type: MetricType::DiskWrittenBytes,
                value: written_bytes as f32,
                timestamp,
            },
        ]
    }
}

impl MetricCollectRepository for MetricCollectRepositoryImpl {
    fn collect(&mut self) -> Vec<Metric> {
        let mut metrics = Vec::new();

        metrics.push(self.cpu_usage());
        metrics.push(self.memory_usage());
        metrics.append(&mut self.network_info());
        metrics.append(&mut self.disk_info());

        metrics
    }
}

#[async_trait::async_trait]
pub trait MetricSendRepository {
    async fn send(&self, metrics: Vec<Metric>) -> anyhow::Result<()>;
}

pub trait MetricStoreRepository {
    fn get_all(&self) -> Vec<Metric>;
    fn set(&self, metrics: Vec<Metric>) -> anyhow::Result<()>;
    fn flush(&self) -> anyhow::Result<()>;
}

pub struct MetricInmemoryStoreRepository {
    metrics: Mutex<Vec<Metric>>,
}

impl MetricInmemoryStoreRepository {
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(Vec::new()),
        }
    }
}

impl MetricStoreRepository for MetricInmemoryStoreRepository {
    fn get_all(&self) -> Vec<Metric> {
        self.metrics.lock().unwrap().clone()
    }

    fn set(&self, metrics: Vec<Metric>) -> anyhow::Result<()> {
        for metric in metrics {
            self.metrics.lock().unwrap().push(metric);
        }
        Ok(())
    }

    fn flush(&self) -> anyhow::Result<()> {
        self.metrics.lock().unwrap().clear();
        Ok(())
    }
}

pub struct MetricFileStoreRepository {
    file_path: String,
}

impl MetricFileStoreRepository {
    pub fn new(file_path: String) -> Self {
        Self { file_path }
    }
}

impl MetricStoreRepository for MetricFileStoreRepository {
    fn get_all(&self) -> Vec<Metric> {
        let file = std::fs::read_to_string(&self.file_path).unwrap();
        serde_json::from_str(&file).unwrap()
    }

    fn set(&self, metrics: Vec<Metric>) -> anyhow::Result<()> {
        let json = serde_json::to_string(&metrics).unwrap();
        std::fs::write(&self.file_path, json).unwrap();
        Ok(())
    }

    // MEMO: This method is not implemented
    fn flush(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct MetricSendRepositoryImpl;

impl MetricSendRepositoryImpl {
    pub fn new() -> Self {
        Self {}
    }
}

// TODO: Implement process for send to Studio.
#[async_trait::async_trait]
impl MetricSendRepository for MetricSendRepositoryImpl {
    async fn send(&self, metrics: Vec<Metric>) -> anyhow::Result<()> {
        for metric in metrics {
            println!("{:?}", metric);
        }
        Ok(())
    }
}
