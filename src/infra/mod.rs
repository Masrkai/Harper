pub mod components;
pub mod shutdown;

pub trait Cleanupable {
    fn cleanup(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>>;
}
