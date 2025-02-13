use crate::did_webvh::infra::did_webvh_data_store::DidWebvhDataStore;

#[derive(Clone)]
pub struct DidWebvhServiceImpl<C: DidWebvhDataStore> {
    pub data_store: C,
}

impl<C: DidWebvhDataStore> DidWebvhServiceImpl<C> {
    pub fn new(data_store: C) -> Self {
        Self { data_store }
    }
}
