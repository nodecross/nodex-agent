use std::sync::{Arc, Mutex};

use crate::repository::metric_repository::{
    Metric, MetricType, MetricsCacheRepository, MetricsWatchRepository, MetricsWithTimestamp,
};
use chrono::{DateTime, Utc};
use sysinfo::{Networks, System};

pub struct MetricsWatchService {
    system: System,
    networks: Networks,
}

pub struct MetricsInMemoryCacheService {
    cache: std::sync::Arc<std::sync::Mutex<Vec<MetricsWithTimestamp>>>,
}

impl MetricsWatchService {
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
        }
    }

    fn memory_usage(&mut self) -> Metric {
        self.system.refresh_memory();
        Metric {
            metric_type: MetricType::MemoryUsage,
            value: self.system.used_memory() as f32,
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

        vec![
            Metric {
                metric_type: MetricType::NetworkReceivedBytes,
                value: received_bytes as f32,
            },
            Metric {
                metric_type: MetricType::NetworkTransmittedBytes,
                value: transmitted_bytes as f32,
            },
            Metric {
                metric_type: MetricType::NetworkReceivedPackets,
                value: received_packets as f32,
            },
            Metric {
                metric_type: MetricType::NetworkTransmittedPackets,
                value: transmitted_packets as f32,
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

        vec![
            Metric {
                metric_type: MetricType::DiskReadBytes,
                value: read_bytes as f32,
            },
            Metric {
                metric_type: MetricType::DiskWrittenBytes,
                value: written_bytes as f32,
            },
        ]
    }
}

impl MetricsWatchRepository for MetricsWatchService {
    fn watch_metrics(&mut self) -> Vec<Metric> {
        let mut metrics = Vec::new();

        metrics.push(self.cpu_usage());
        metrics.push(self.memory_usage());
        metrics.append(&mut self.network_info());
        metrics.append(&mut self.disk_info());

        metrics
    }
}

impl MetricsCacheRepository for MetricsInMemoryCacheService {
    fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn push(&mut self, timestamp: DateTime<Utc>, metrics: Vec<Metric>) {
        let mut cache = self.cache.lock().unwrap();
        cache.push(MetricsWithTimestamp { timestamp, metrics });
    }

    fn clear(&mut self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    fn get(&mut self) -> Vec<MetricsWithTimestamp> {
        let cache = self.cache.lock().unwrap();
        cache.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_usage() {
        let mut service = MetricsWatchService::new();
        let cpu_usage = service.cpu_usage();
        assert!(cpu_usage.value >= 0.0);
        assert!(cpu_usage.metric_type == MetricType::CpuUsage);
    }

    #[test]
    fn test_memory_usage() {
        let mut service = MetricsWatchService::new();
        let memory_usage = service.memory_usage();
        assert!(memory_usage.value >= 0.0);
        assert!(memory_usage.metric_type == MetricType::MemoryUsage);
    }

    #[test]
    fn test_network_info() {
        let mut service = MetricsWatchService::new();
        let network_metrics = service.network_info();
        for network_metric in network_metrics {
            assert!(network_metric.value >= 0.0);
            assert!(
                network_metric.metric_type == MetricType::NetworkReceivedBytes
                    || network_metric.metric_type == MetricType::NetworkTransmittedBytes
                    || network_metric.metric_type == MetricType::NetworkReceivedPackets
                    || network_metric.metric_type == MetricType::NetworkTransmittedPackets
            );
        }
    }

    #[test]
    fn test_disk_info() {
        let mut service = MetricsWatchService::new();
        let disk_metrics = service.disk_info();
        for disk_metric in disk_metrics {
            assert!(disk_metric.value >= 0.0);
            assert!(
                disk_metric.metric_type == MetricType::DiskReadBytes
                    || disk_metric.metric_type == MetricType::DiskWrittenBytes
            );
        }
    }

    #[test]
    fn test_watch_metrics() {
        let mut service = MetricsWatchService::new();
        let metrics = service.watch_metrics();
        assert!(metrics.len() == 8);
    }
}
