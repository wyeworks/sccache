// Copyright 2026 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cooldowns after repeated Action Cache RPC failures.

use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

pub(super) const FAILURES_TO_PAUSE: u32 = 3;
const PAUSE_MIN: Duration = Duration::from_secs(5);
const PAUSE_MAX: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct LookupPause {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    failures_in_a_row: u32,
    pauses_in_a_row: u32,
    paused_until: Option<Instant>,
    probe_in_flight: bool,
    generation: u64,
}

impl State {
    fn is_paused(&self) -> bool {
        self.paused_until
            .is_some_and(|until| Instant::now() < until)
            || self.probe_in_flight
    }
}

/// Dropping an unfinished probe releases it, including when its task is cancelled.
pub(super) struct LookupPermit<'a> {
    pause: &'a LookupPause,
    generation: u64,
    probe: bool,
    finished: bool,
}

impl LookupPause {
    pub(super) fn is_paused(&self) -> bool {
        self.state.lock().unwrap().is_paused()
    }

    pub(super) fn try_lookup(&self) -> Option<LookupPermit<'_>> {
        let mut state = self.state.lock().unwrap();
        if state.is_paused() {
            return None;
        }
        let probe = state.pauses_in_a_row != 0;
        state.probe_in_flight = probe;
        Some(LookupPermit {
            pause: self,
            generation: state.generation,
            probe,
            finished: false,
        })
    }
}

impl LookupPermit<'_> {
    pub(super) fn succeeded(mut self) {
        self.finished = true;
        let mut state = self.pause.state.lock().unwrap();
        if self.generation != state.generation {
            return;
        }
        if self.probe {
            *state = State {
                generation: state.generation.wrapping_add(1),
                ..Default::default()
            };
        } else {
            state.failures_in_a_row = 0;
        }
    }

    pub(super) fn failed(mut self) -> Option<Duration> {
        self.finished = true;
        let mut state = self.pause.state.lock().unwrap();
        // Responses from before a pause must not change the current recovery attempt.
        if self.generation != state.generation {
            return None;
        }
        state.failures_in_a_row = state.failures_in_a_row.saturating_add(1);
        if state.pauses_in_a_row == 0 && state.failures_in_a_row < FAILURES_TO_PAUSE {
            return None;
        }
        let pause = PAUSE_MIN
            .saturating_mul(2u32.saturating_pow(state.pauses_in_a_row))
            .min(PAUSE_MAX);
        *state = State {
            failures_in_a_row: 0,
            pauses_in_a_row: state.pauses_in_a_row.saturating_add(1),
            paused_until: Some(Instant::now() + pause),
            probe_in_flight: false,
            generation: state.generation.wrapping_add(1),
        };
        Some(pause)
    }
}

impl Drop for LookupPermit<'_> {
    fn drop(&mut self) {
        if self.probe && !self.finished {
            let mut state = self.pause.state.lock().unwrap();
            if self.generation == state.generation {
                state.probe_in_flight = false;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::{Barrier, Notify};

    fn fail(pause: &LookupPause, times: u32) -> Option<Duration> {
        (0..times)
            .filter_map(|_| pause.try_lookup().unwrap().failed())
            .last()
    }

    #[tokio::test(start_paused = true)]
    async fn test_lookups_resume_at_the_end_of_the_cooldown() {
        let pause = LookupPause::default();
        assert_eq!(None, fail(&pause, FAILURES_TO_PAUSE - 1));
        assert!(!pause.is_paused());
        assert_eq!(Some(PAUSE_MIN), fail(&pause, 1));
        assert!(pause.is_paused());
        assert!(pause.try_lookup().is_none());
        tokio::time::advance(PAUSE_MIN - Duration::from_nanos(1)).await;
        assert!(pause.try_lookup().is_none());
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(pause.try_lookup().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_successful_responses_reset_failures_and_backoff() {
        let pause = LookupPause::default();
        fail(&pause, FAILURES_TO_PAUSE - 1);
        pause.try_lookup().unwrap().succeeded();
        assert_eq!(None, fail(&pause, FAILURES_TO_PAUSE - 1));
        assert_eq!(Some(PAUSE_MIN), fail(&pause, 1));
        tokio::time::advance(PAUSE_MIN).await;
        assert_eq!(Some(PAUSE_MIN * 2), fail(&pause, 1));
        tokio::time::advance(PAUSE_MIN * 2).await;
        pause.try_lookup().unwrap().succeeded();
        assert!(!pause.is_paused());
        assert_eq!(Some(PAUSE_MIN), fail(&pause, FAILURES_TO_PAUSE));
    }

    #[tokio::test(start_paused = true)]
    async fn test_pauses_double_up_to_the_max() {
        let pause = LookupPause::default();
        let mut duration = fail(&pause, FAILURES_TO_PAUSE).unwrap();
        for seconds in [5, 10, 20, 40, 60, 60] {
            assert_eq!(duration.as_secs(), seconds);
            tokio::time::advance(duration).await;
            duration = fail(&pause, 1).unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_old_responses_do_not_change_the_current_pause_or_probe() {
        let pause = LookupPause::default();
        let late_success = pause.try_lookup().unwrap();
        let late_failure = pause.try_lookup().unwrap();
        let even_later_failure = pause.try_lookup().unwrap();
        fail(&pause, FAILURES_TO_PAUSE);
        tokio::time::advance(PAUSE_MIN / 2).await;
        assert_eq!(None, late_failure.failed());
        tokio::time::advance(PAUSE_MIN / 2).await;
        let probe = pause.try_lookup().unwrap();
        late_success.succeeded();
        assert_eq!(None, even_later_failure.failed());
        assert!(pause.try_lookup().is_none());
        assert_eq!(Some(PAUSE_MIN * 2), probe.failed());
    }

    #[tokio::test(start_paused = true)]
    async fn test_only_one_concurrent_lookup_probes_after_a_pause() {
        let pause = Arc::new(LookupPause::default());
        fail(&pause, FAILURES_TO_PAUSE);
        tokio::time::advance(PAUSE_MIN).await;
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = vec![];
        for _ in 0..8 {
            let pause = pause.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let permit = pause.try_lookup();
                let admitted = permit.is_some();
                barrier.wait().await;
                drop(permit);
                admitted
            }));
        }
        let mut probes = 0;
        for task in tasks {
            probes += u32::from(task.await.unwrap());
        }
        assert_eq!(probes, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_cancelling_a_probe_releases_it_immediately() {
        let pause = Arc::new(LookupPause::default());
        fail(&pause, FAILURES_TO_PAUSE);
        tokio::time::advance(PAUSE_MIN).await;
        let ready = Arc::new(Notify::new());
        let task = {
            let pause = pause.clone();
            let ready = ready.clone();
            tokio::spawn(async move {
                let _permit = pause.try_lookup().unwrap();
                ready.notify_one();
                std::future::pending::<()>().await;
            })
        };
        ready.notified().await;
        assert!(pause.try_lookup().is_none());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(pause.try_lookup().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_many_pauses_keep_the_maximum_backoff() {
        let pause = LookupPause::default();
        pause.state.lock().unwrap().pauses_in_a_row = u32::MAX;
        assert_eq!(Some(PAUSE_MAX), pause.try_lookup().unwrap().failed());
        tokio::time::advance(PAUSE_MAX).await;
        assert_eq!(Some(PAUSE_MAX), pause.try_lookup().unwrap().failed());
    }
}
