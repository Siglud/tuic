use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Authenticated(Arc<AuthenticatedInner>);

struct AuthenticatedInner {
    uuid: AtomicCell<Option<Uuid>>,
    broadcast: Mutex<Vec<Waker>>,
}

impl Authenticated {
    pub fn new() -> Self {
        Self(Arc::new(AuthenticatedInner {
            uuid: AtomicCell::new(None),
            broadcast: Mutex::new(Vec::new()),
        }))
    }

    pub fn set(&self, uuid: Uuid) {
        self.0.uuid.store(Some(uuid));

        for waker in self.0.broadcast.lock().drain(..) {
            waker.wake();
        }
    }

    pub fn get(&self) -> Option<Uuid> {
        self.0.uuid.load()
    }
}

impl Future for Authenticated {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut broadcast = self.0.broadcast.lock();

        if self.get().is_some() {
            Poll::Ready(())
        } else {
            if !broadcast.iter().any(|waker| waker.will_wake(cx.waker())) {
                broadcast.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl Display for Authenticated {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(uuid) = self.get() {
            write!(f, "{uuid}")
        } else {
            write!(f, "unauthenticated")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct WakeCounter(AtomicUsize);

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn poll_with(auth: &mut Authenticated, waker: &Waker) -> Poll<()> {
        let mut context = Context::from_waker(waker);
        Pin::new(auth).poll(&mut context)
    }

    #[test]
    fn starts_unauthenticated_and_displays_state() {
        let auth = Authenticated::new();

        assert_eq!(auth.get(), None);
        assert_eq!(auth.to_string(), "unauthenticated");
    }

    #[test]
    fn pending_poll_registers_each_waiter_once() {
        let auth = Authenticated::new();
        let first_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let second_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let first_waker = Waker::from(first_counter.clone());
        let second_waker = Waker::from(second_counter.clone());
        let mut first = auth.clone();
        let mut second = auth.clone();

        assert_eq!(poll_with(&mut first, &first_waker), Poll::Pending);
        assert_eq!(poll_with(&mut first, &first_waker), Poll::Pending);
        assert_eq!(poll_with(&mut second, &second_waker), Poll::Pending);
        assert_eq!(auth.0.broadcast.lock().len(), 2);

        auth.set(Uuid::nil());
        assert_eq!(first_counter.0.load(Ordering::SeqCst), 1);
        assert_eq!(second_counter.0.load(Ordering::SeqCst), 1);
        assert!(auth.0.broadcast.lock().is_empty());
    }

    #[test]
    fn set_makes_all_clones_ready_and_updates_display() {
        let auth = Authenticated::new();
        let uuid = Uuid::from_u128(0x00112233_4455_6677_8899_aabbccddeeff);
        let mut waiter = auth.clone();
        let waker = Waker::noop();

        auth.set(uuid);

        assert_eq!(waiter.get(), Some(uuid));
        assert_eq!(waiter.to_string(), uuid.to_string());
        assert_eq!(poll_with(&mut waiter, waker), Poll::Ready(()));
        assert!(auth.0.broadcast.lock().is_empty());
    }
}
