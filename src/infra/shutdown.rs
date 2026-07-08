use crate::infra::Cleanupable;

pub struct ShutdownManager {
    components: Vec<Box<dyn Cleanupable>>,
}

impl ShutdownManager {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn add(&mut self, component: Box<dyn Cleanupable>) {
        self.components.push(component);
    }

    pub async fn shutdown(&mut self) {
        for component in self.components.iter_mut().rev() {
            if let Err(e) = component.cleanup().await {
                eprintln!("[!] Shutdown error: {}", e);
            }
        }
    }
}
