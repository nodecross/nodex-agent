#[cfg(test)]
mod tests {
    use protocol::did_webvh::domain::did::DidWebvh;
    use protocol::did_webvh::domain::did_log_entry::DidLogEntry;
    use protocol::did_webvh::infra::did_webvh_data_store::{
        DidLogEntryResponse, DidWebvhDataStore,
    };
    use protocol::did_webvh::service::controller::controller_service::DidWebvhControllerService;
    use protocol::did_webvh::service::service_impl::DidWebvhServiceImpl;
    use protocol::keyring::*;
    use rand_core::OsRng;

    struct MockDataStore {}
    impl MockDataStore {
        fn new() -> Self {
            MockDataStore {}
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum MockDataStoreError {
        #[error("error: {0}")]
        JsonError(#[from] serde_json::Error),
    }
    impl DidWebvhDataStore for MockDataStore {
        type Error = MockDataStoreError;
        async fn post(&self, _path: &str, body: &str) -> Result<DidLogEntryResponse, Self::Error> {
            let log_entry: DidLogEntry = serde_json::from_str(body)?;
            let doc = log_entry.state;
            let serialized_doc = serde_json::to_string(&doc)?;
            let response = DidLogEntryResponse::new(http::StatusCode::OK, serialized_doc);
            Ok(response)
        }
        async fn get(&self, _path: &str) -> Result<DidLogEntryResponse, Self::Error> {
            unimplemented!()
        }
        async fn put(
            &self,
            _path: &str,
            _body: &str,
        ) -> Result<Vec<DidLogEntryResponse>, Self::Error> {
            unimplemented!()
        }
        async fn delete(&self, _path: &str) -> Result<Vec<DidLogEntryResponse>, Self::Error> {
            unimplemented!()
        }
    }

    #[tokio::test]
    pub async fn test_create_did_log_entry() {
        let keyring = keypair::KeyPairing::create_keyring(OsRng);
        let datastore = MockDataStore::new();
        let res = DidWebvhServiceImpl::new(datastore)
            .create_identifier("domain.examle.com/test/did", true, keyring)
            .await
            .unwrap();
        assert_eq!(res.id.get_method(), "webvh");
        let webvh_did: DidWebvh = res.id.clone().try_into().unwrap();
        assert_eq!(webvh_did.get_did(), &res.id);
        assert_eq!(webvh_did.get_uri(), "domain.examle.com:test:did");
    }
}
