use crate::repository::metric_repository::{DiskMetrics, MetricWatchRepository, NetworkMetrics};
use sysinfo::{Networks, System};

pub struct MetricsWatchService {
    system: System,
    networks: Networks,
}

impl MetricsWatchService {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            networks: Networks::new(),
        }
    }
}

impl MetricWatchRepository for MetricsWatchService {
    fn cpu_usage(&mut self) -> f32 {
        self.system.refresh_cpu_usage();
        self.system.global_cpu_info().cpu_usage()
    }

    fn memory_usage(&mut self) -> f32 {
        self.system.refresh_memory();
        self.system.used_memory() as f32
    }

    fn network_info(&mut self) -> NetworkMetrics {
        let mut received_bytes = 0;
        let mut transmitted_bytes = 0;
        let mut recceived_packets = 0;
        let mut transmitted_packets = 0;

        self.networks.refresh_list();
        for network in self.networks.list().values() {
            received_bytes += network.received();
            transmitted_bytes += network.transmitted();
            recceived_packets += network.packets_received();
            transmitted_packets += network.packets_transmitted();
        }
        NetworkMetrics {
            received_bytes: received_bytes as f32,
            transmitted_bytes: transmitted_bytes as f32,
            recceived_packets: recceived_packets as f32,
            transmitted_packets: transmitted_packets as f32,
        }
    }

    fn disk_info(&mut self) -> DiskMetrics {
        let mut read_bytes = 0;
        let mut written_bytes = 0;

        self.system.refresh_processes();
        for process in self.system.processes().values() {
            let disk_usage = process.disk_usage();
            read_bytes += disk_usage.read_bytes;
            written_bytes += disk_usage.written_bytes;
        }
        DiskMetrics {
            read_bytes: read_bytes as f32,
            written_bytes: written_bytes as f32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::metric_repository::MetricWatchRepository;

    #[test]
    fn test_cpu_usage() {
        let mut service = MetricsWatchService::new();
        let cpu_usage = service.cpu_usage();
        assert!(cpu_usage >= 0.0);
    }

    #[test]
    fn test_memory_usage() {
        let mut service = MetricsWatchService::new();
        let memory_usage = service.memory_usage();
        assert!(memory_usage >= 0.0);
    }

    #[test]
    fn test_network_info() {
        let mut service = MetricsWatchService::new();
        let network_info = service.network_info();
        assert!(network_info.received_bytes >= 0.0);
        assert!(network_info.transmitted_bytes >= 0.0);
        assert!(network_info.recceived_packets >= 0.0);
        assert!(network_info.transmitted_packets >= 0.0);
    }

    #[test]
    fn test_disk_info() {
        let mut service = MetricsWatchService::new();
        let disk_info = service.disk_info();
        assert!(disk_info.read_bytes >= 0.0);
        assert!(disk_info.written_bytes >= 0.0);
    }
}
