use std::sync::mpsc::{self, Receiver, Sender};

#[derive(Debug, PartialEq, Eq)]
pub enum ShutdownError {
    HandlerSetup,
    ListenerDisconnected,
}

pub fn wait_for_ctrl_c() -> Result<(), ShutdownError> {
    wait_with(register_handler)
}

fn wait_with<R>(register: R) -> Result<(), ShutdownError>
where
    R: FnOnce(Sender<()>) -> Result<(), ShutdownError>,
{
    let (sender, receiver) = mpsc::channel();
    register(sender)?;
    wait_on_receiver(receiver)
}

fn register_handler(sender: Sender<()>) -> Result<(), ShutdownError> {
    ctrlc::set_handler(build_handler(sender)).map_err(|_| ShutdownError::HandlerSetup)
}

fn build_handler(sender: Sender<()>) -> impl FnMut() + Send + 'static {
    move || {
        let _ = sender.send(());
    }
}

fn wait_on_receiver(receiver: Receiver<()>) -> Result<(), ShutdownError> {
    receiver
        .recv()
        .map_err(|_| ShutdownError::ListenerDisconnected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn wait_with_returns_when_sender_notifies() {
        let result = wait_with(|sender| {
            sender.send(()).unwrap();
            Ok(())
        });

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn wait_with_propagates_registration_error() {
        let result = wait_with(|_| Err(ShutdownError::HandlerSetup));

        assert_eq!(result, Err(ShutdownError::HandlerSetup));
    }

    #[test]
    fn wait_on_receiver_detects_disconnection() {
        let (_, receiver) = mpsc::channel();

        assert_eq!(
            wait_on_receiver(receiver),
            Err(ShutdownError::ListenerDisconnected)
        );
    }

    #[test]
    fn build_handler_notifies_sender() {
        let (sender, receiver) = mpsc::channel();
        let mut handler = build_handler(sender);

        handler();

        assert_eq!(receiver.recv().unwrap(), ());
    }
}
