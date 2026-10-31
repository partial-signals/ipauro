//! # ipauro-bridge — clock-domain bridge for a Protocol-NAT leg (R010-F4)
//!
//! A transcode leg joins two protocols whose media clocks do not agree: Dante
//! (PTPv1), AVB (gPTP), AES67 (PTPv2) are mutually incompatible, and LinkAudio
//! and the JackTrip family discipline no rate at all (A004 §3). The prior art
//! settled what to do about it (A003 §2, R010-F4 gotcha): **do not try to sync
//! the clocks — adaptively resample at the receiver**, with an adaptive jitter
//! buffer, the way JackTrip / zita-njbridge / SonoBus do. The ASRC kernel itself
//! is borrowed, not written here; **this crate is the controller** that drives
//! it, which is the half that is ours:
//!
//! - [`DriftEstimator`] — the sender's true rate relative to nominal, from
//!   arrival times and frame counts alone (no clock protocol needed). A sliding
//!   least-squares fit, so zero-mean arrival jitter cancels instead of leaking
//!   into the ratio.
//! - [`JitterStats`] — arrival-jitter RMS, which sets how deep the buffer must
//!   be to survive it.
//! - [`LegClock`] — the controller: drift ratio × a small fill-steering term
//!   (consume faster when the buffer runs long, slower when short), clamped to
//!   the [`BridgePolicy`] bounds, and a buffer-depth target that follows jitter.
//! - [`BridgePolicy`] — what the leg's class allows, derived from the mesh's
//!   [`ClockBridge`] verdict: a shared PTP domain may only drift ppm, so the
//!   ratio is held near unity; two disciplined-but-different references get a
//!   steady but wider band; an undisciplined side gets the full adaptive range.
//!
//! Policy comes from the class, never from protocol identity — the mesh already
//! reduced "Dante → AVB" to `CrossDomain`; nothing here asks which protocol.
//!
//! ## Status / phases
//!
//! **P1:** controller + policy, hardware-free, run in the control-plane CI
//! container. The kernel is the [`Resampler`] trait.
//! **P2:** [`kernel::RubatoKernel`] — the `rubato` async sinc resampler behind
//! that trait (A004 §3 names rubato as the R010-F4 ASRC), and the loopback test
//! `tests::loopback_holds_the_buffer_against_a_fast_sender` that pushes a
//! 0.2 %-fast synthetic stream through controller + kernel for 20 s.
//! **P3:** boundary-clock mode for a leg that demands hardware PTP on *both*
//! ends (the exception the gotcha allows), only if R010-T5 shows a need; and
//! `process_into_buffer` with a caller-owned output in the RT path.

pub mod kernel;

use ipauro_mesh::protocol::ClockBridge;
use std::collections::VecDeque;

/// One million — ratio ↔ ppm.
const PPM: f64 = 1e6;

/// An ASRC kernel the controller drives. The one verb the controller needs:
/// the output/input rate ratio to apply from now on. Implementations: the
/// rubato adapter (P2); tests use a recorder.
pub trait Resampler {
    /// `ratio` > 1 consumes input faster than nominal (the sender runs fast).
    fn set_ratio(&mut self, ratio: f64);
}

/// What the leg's clock class permits. Derived, not configured.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct BridgePolicy {
    /// Largest |ratio − 1| the controller may apply, in ppm. An estimate beyond
    /// it is clamped and reported ([`LegClock::is_clamped`]) — on a shared PTP
    /// domain that means the domain is lying, not that we should follow it.
    pub max_ppm: f64,
    /// Whether the fill-steering term runs. Off for disciplined references:
    /// their rate is right by construction, so steering would only add wow.
    pub steer_fill: bool,
    /// Buffer depth bounds, frames.
    pub min_depth: u32,
    pub max_depth: u32,
}

impl BridgePolicy {
    /// The policy for a leg the mesh classified. `NoMedia` has nothing to
    /// bridge and returns `None` — a caller holding one has a planning bug.
    pub fn for_class(class: ClockBridge) -> Option<BridgePolicy> {
        Some(match class {
            // Same network reference: crystals are slaved, residual is the
            // reference's own ppm. Near-unity only (A001 R005-T9 gotcha).
            ClockBridge::SharedDomain => BridgePolicy { max_ppm: 50.0, steer_fill: false, min_depth: 64, max_depth: 1_024 },
            // Two steady references that disagree by a fixed ppm: follow the
            // measured offset, no steering.
            ClockBridge::CrossDomain => BridgePolicy { max_ppm: 500.0, steer_fill: false, min_depth: 128, max_depth: 4_096 },
            // At least one side free-runs: divergence is unbounded, so the
            // full JackTrip/SonoBus treatment — track it and steer the fill.
            ClockBridge::Adaptive => BridgePolicy { max_ppm: 5_000.0, steer_fill: true, min_depth: 256, max_depth: 16_384 },
            ClockBridge::NoMedia => return None,
            // No visible row for one side: nothing to size a policy from.
            ClockBridge::Unknown => return None,
        })
    }
}

/// Sliding least-squares estimate of the sender's rate from
/// (arrival time, cumulative frames) observations. Arrival jitter is zero-mean
/// noise on the time axis and averages out over the window; a systematic rate
/// error does not. Window length trades convergence speed for noise rejection.
#[derive(Clone, Debug)]
pub struct DriftEstimator {
    nominal_hz: f64,
    window: usize,
    /// (t seconds, frames) pairs, oldest first.
    obs: VecDeque<(f64, f64)>,
}

impl DriftEstimator {
    pub fn new(nominal_hz: u32, window: usize) -> Self {
        Self { nominal_hz: nominal_hz as f64, window: window.max(2), obs: VecDeque::new() }
    }

    /// Record that `cumulative_frames` had arrived by `arrival_ns`.
    pub fn observe(&mut self, arrival_ns: u64, cumulative_frames: u64) {
        if self.obs.len() == self.window {
            self.obs.pop_front();
        }
        self.obs.push_back((arrival_ns as f64 * 1e-9, cumulative_frames as f64));
    }

    /// Measured rate / nominal rate. `None` until two observations exist or
    /// while all observations share one timestamp.
    pub fn ratio(&self) -> Option<f64> {
        let n = self.obs.len() as f64;
        if n < 2.0 {
            return None;
        }
        // Centre both axes before fitting: times are large (ns since boot) and
        // the products would otherwise lose the ppm we are looking for.
        let (mt, mf) = self.obs.iter().fold((0.0, 0.0), |(a, b), (t, f)| (a + t, b + f));
        let (mt, mf) = (mt / n, mf / n);
        let (mut sxy, mut sxx) = (0.0, 0.0);
        for (t, f) in &self.obs {
            sxy += (t - mt) * (f - mf);
            sxx += (t - mt) * (t - mt);
        }
        if sxx <= 0.0 {
            return None;
        }
        Some((sxy / sxx) / self.nominal_hz)
    }

    /// The same, in ppm from nominal.
    pub fn ppm(&self) -> Option<f64> {
        self.ratio().map(|r| (r - 1.0) * PPM)
    }
}

/// Arrival-jitter statistics: RMS deviation of each inter-arrival gap from the
/// gap its frame count predicts at nominal rate. Exponentially weighted so it
/// tracks a link whose jitter changes (Wi-Fi contention comes and goes).
#[derive(Clone, Debug)]
pub struct JitterStats {
    nominal_hz: f64,
    alpha: f64,
    last: Option<(u64, u64)>,
    mean_sq_s: f64,
}

impl JitterStats {
    /// `alpha` in (0, 1]: weight of the newest sample (0.05 ≈ a 20-packet memory).
    pub fn new(nominal_hz: u32, alpha: f64) -> Self {
        Self { nominal_hz: nominal_hz as f64, alpha: alpha.clamp(1e-3, 1.0), last: None, mean_sq_s: 0.0 }
    }

    pub fn observe(&mut self, arrival_ns: u64, cumulative_frames: u64) {
        if let Some((t0, f0)) = self.last {
            let dt = (arrival_ns.saturating_sub(t0)) as f64 * 1e-9;
            let expected = (cumulative_frames.saturating_sub(f0)) as f64 / self.nominal_hz;
            let dev = dt - expected;
            self.mean_sq_s += self.alpha * (dev * dev - self.mean_sq_s);
        }
        self.last = Some((arrival_ns, cumulative_frames));
    }

    /// Jitter RMS in frames at nominal rate.
    pub fn rms_frames(&self) -> f64 {
        self.mean_sq_s.sqrt() * self.nominal_hz
    }
}

/// The per-leg controller. Feed it every packet's arrival and the buffer's
/// current fill; read the ratio to hand the kernel and the depth to hold.
#[derive(Clone, Debug)]
pub struct LegClock {
    policy: BridgePolicy,
    drift: DriftEstimator,
    jitter: JitterStats,
    /// Fill-steering gain: fraction of full-scale ratio correction applied per
    /// unit of normalized fill error. Small on purpose — steering is a nudge
    /// that keeps the buffer centred, not a second rate estimator.
    steer_gain: f64,
    /// Headroom multiplier on jitter RMS when choosing depth: how many sigmas
    /// of arrival jitter the buffer absorbs before an underrun.
    jitter_sigmas: f64,
    fill_frames: Option<u32>,
    clamped: bool,
}

impl LegClock {
    /// `nominal_hz` is the leg's declared sample rate (48 k is the One Rate).
    pub fn new(policy: BridgePolicy, nominal_hz: u32) -> Self {
        Self {
            policy,
            // ~4 s of 1 ms packets. Slope noise from arrival jitter falls as
            // (window span × √n); with ±300 µs jitter this window reads to
            // well under 1 ppm, where a 256-packet one would wander by ~150.
            drift: DriftEstimator::new(nominal_hz, 4_096),
            jitter: JitterStats::new(nominal_hz, 0.05),
            steer_gain: 0.1,
            jitter_sigmas: 4.0,
            fill_frames: None,
            clamped: false,
        }
    }

    pub fn policy(&self) -> &BridgePolicy {
        &self.policy
    }

    /// A packet carrying frames up to `cumulative_frames` arrived at
    /// `arrival_ns`, and the jitter buffer currently holds `fill_frames`.
    pub fn observe(&mut self, arrival_ns: u64, cumulative_frames: u64, fill_frames: u32) {
        self.drift.observe(arrival_ns, cumulative_frames);
        self.jitter.observe(arrival_ns, cumulative_frames);
        self.fill_frames = Some(fill_frames);
    }

    /// Buffer depth to hold, frames: enough to absorb `jitter_sigmas` of
    /// arrival jitter, within the policy's bounds. Monotone in jitter.
    pub fn target_depth_frames(&self) -> u32 {
        let want = (self.jitter.rms_frames() * self.jitter_sigmas).ceil();
        (want as u32).clamp(self.policy.min_depth, self.policy.max_depth)
    }

    /// The ratio to apply now: measured drift, nudged toward the depth target
    /// when the policy steers, clamped to the policy band. Unity until the
    /// estimator has enough to say anything.
    pub fn ratio(&mut self) -> f64 {
        let mut r = self.drift.ratio().unwrap_or(1.0);
        if self.policy.steer_fill
            && let Some(fill) = self.fill_frames
        {
            let target = self.target_depth_frames().max(1) as f64;
            // Normalized fill error in [-1, ∞): long buffer → positive → consume faster.
            let err = (fill as f64 - target) / target;
            r *= 1.0 + self.steer_gain * (self.policy.max_ppm / PPM) * err.clamp(-1.0, 1.0);
        }
        let band = self.policy.max_ppm / PPM;
        let clamped = r.clamp(1.0 - band, 1.0 + band);
        self.clamped = clamped != r;
        clamped
    }

    /// Whether the last [`ratio`](Self::ratio) hit the policy band. On a
    /// `SharedDomain` leg this is a fault to surface (the domain is not what
    /// the census said), not a condition to ride.
    pub fn is_clamped(&self) -> bool {
        self.clamped
    }

    /// Current drift estimate in ppm, if any (diagnostics / status surface).
    pub fn drift_ppm(&self) -> Option<f64> {
        self.drift.ppm()
    }

    /// Current arrival-jitter RMS in frames (diagnostics / status surface).
    pub fn jitter_rms_frames(&self) -> f64 {
        self.jitter.rms_frames()
    }

    /// Observe and push the resulting ratio into the kernel in one step — the
    /// per-packet call an adapter makes.
    pub fn drive<R: Resampler>(&mut self, kernel: &mut R, arrival_ns: u64, cumulative_frames: u64, fill_frames: u32) -> f64 {
        self.observe(arrival_ns, cumulative_frames, fill_frames);
        let r = self.ratio();
        kernel.set_ratio(r);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG so jitter is reproducible without a dependency.
    struct Lcg(u64);
    impl Lcg {
        fn next_unit(&mut self) -> f64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((self.0 >> 11) as f64) / ((1u64 << 53) as f64)
        }
        /// Uniform in [-a, a].
        fn jitter(&mut self, a: f64) -> f64 {
            (self.next_unit() * 2.0 - 1.0) * a
        }
    }

    struct Recorder(Vec<f64>);
    impl Resampler for Recorder {
        fn set_ratio(&mut self, ratio: f64) {
            self.0.push(ratio);
        }
    }

    const HZ: u32 = 48_000;
    const FRAMES_PER_PKT: u64 = 48; // 1 ms packets

    /// A sender whose crystal runs `ppm` fast, over a link with ±`jitter_us`
    /// uniform arrival jitter. Yields (arrival_ns, cumulative_frames).
    fn sender(ppm: f64, jitter_us: f64, packets: usize, seed: u64) -> Vec<(u64, u64)> {
        let mut rng = Lcg(seed);
        let true_hz = HZ as f64 * (1.0 + ppm / 1e6);
        (1..=packets as u64)
            .map(|i| {
                let frames = i * FRAMES_PER_PKT;
                let t_s = frames as f64 / true_hz + rng.jitter(jitter_us) * 1e-6;
                ((t_s * 1e9) as u64, frames)
            })
            .collect()
    }

    #[test]
    fn drift_estimate_converges_through_jitter() {
        // 20 s of 1 ms packets with ±300 µs jitter: the fit reads the slope to
        // a fraction of a ppm. (Short windows cannot — see LegClock::new.)
        let mut est = DriftEstimator::new(HZ, 20_000);
        for (t, f) in sender(200.0, 300.0, 20_000, 1) {
            est.observe(t, f);
        }
        let ppm = est.ppm().unwrap();
        assert!((ppm - 200.0).abs() < 5.0, "estimated {ppm} ppm, expected ~200");

        // And the sign is right the other way.
        let mut est = DriftEstimator::new(HZ, 20_000);
        for (t, f) in sender(-120.0, 300.0, 20_000, 2) {
            est.observe(t, f);
        }
        let ppm = est.ppm().unwrap();
        assert!((ppm + 120.0).abs() < 5.0, "estimated {ppm} ppm, expected ~-120");
    }

    #[test]
    fn estimator_is_silent_until_it_can_speak() {
        let mut est = DriftEstimator::new(HZ, 8);
        assert_eq!(est.ratio(), None);
        est.observe(1_000, 48);
        assert_eq!(est.ratio(), None, "one point is not a slope");
        est.observe(1_000, 96);
        assert_eq!(est.ratio(), None, "two points at one instant are not a slope either");
        est.observe(2_000_000, 144);
        assert!(est.ratio().is_some());
    }

    #[test]
    fn jitter_rms_tracks_the_link() {
        let mut quiet = JitterStats::new(HZ, 0.05);
        for (t, f) in sender(0.0, 10.0, 500, 3) {
            quiet.observe(t, f);
        }
        let mut noisy = JitterStats::new(HZ, 0.05);
        for (t, f) in sender(0.0, 2_000.0, 500, 4) {
            noisy.observe(t, f);
        }
        assert!(quiet.rms_frames() < 1.0, "10 µs jitter is under a frame: {}", quiet.rms_frames());
        assert!(noisy.rms_frames() > 40.0, "2 ms uniform jitter is tens of frames: {}", noisy.rms_frames());
        assert!(noisy.rms_frames() > quiet.rms_frames() * 20.0);
    }

    #[test]
    fn policy_follows_the_mesh_class_not_the_protocol() {
        let shared = BridgePolicy::for_class(ClockBridge::SharedDomain).unwrap();
        let cross = BridgePolicy::for_class(ClockBridge::CrossDomain).unwrap();
        let adaptive = BridgePolicy::for_class(ClockBridge::Adaptive).unwrap();
        assert!(shared.max_ppm < cross.max_ppm && cross.max_ppm < adaptive.max_ppm);
        assert!(!shared.steer_fill && !cross.steer_fill && adaptive.steer_fill);
        assert!(shared.max_depth <= cross.max_depth && cross.max_depth <= adaptive.max_depth);
        assert_eq!(BridgePolicy::for_class(ClockBridge::NoMedia), None);
    }

    /// A shared-domain leg that measures 200 ppm is clamped to the band and says
    /// so: the domain is not what the census claimed.
    #[test]
    fn shared_domain_clamps_and_reports_an_out_of_band_drift() {
        let mut clock = LegClock::new(BridgePolicy::for_class(ClockBridge::SharedDomain).unwrap(), HZ);
        for (t, f) in sender(200.0, 50.0, 5_000, 5) {
            clock.observe(t, f, 256);
        }
        let r = clock.ratio();
        assert!(clock.is_clamped());
        assert!(((r - 1.0) * 1e6 - 50.0).abs() < 1e-6, "clamped to +50 ppm, got {}", (r - 1.0) * 1e6);

        // The same drift on an adaptive leg is simply followed.
        let mut clock = LegClock::new(BridgePolicy::for_class(ClockBridge::Adaptive).unwrap(), HZ);
        for (t, f) in sender(200.0, 50.0, 5_000, 5) {
            clock.observe(t, f, clock.target_depth_frames());
        }
        let r = clock.ratio();
        assert!(!clock.is_clamped());
        assert!(((r - 1.0) * 1e6 - 200.0).abs() < 5.0, "followed to ~200 ppm, got {}", (r - 1.0) * 1e6);
    }

    /// Fill steering: with the buffer long the adaptive leg consumes faster
    /// than drift alone says; short, slower. Disciplined legs never steer.
    #[test]
    fn fill_steering_nudges_toward_the_depth_target() {
        let obs = sender(0.0, 50.0, 600, 6);
        let run = |class, fill: u32| {
            let mut clock = LegClock::new(BridgePolicy::for_class(class).unwrap(), HZ);
            for &(t, f) in &obs {
                clock.observe(t, f, fill);
            }
            clock.ratio()
        };
        let target = {
            let mut c = LegClock::new(BridgePolicy::for_class(ClockBridge::Adaptive).unwrap(), HZ);
            for &(t, f) in &obs {
                c.observe(t, f, 0);
            }
            c.target_depth_frames()
        };
        let centred = run(ClockBridge::Adaptive, target);
        let long = run(ClockBridge::Adaptive, target * 2);
        let short = run(ClockBridge::Adaptive, 0);
        assert!(long > centred && centred > short, "long {long} > centred {centred} > short {short}");
        // Steering is a nudge: well inside the band even at full error.
        assert!((long - 1.0) * 1e6 < 5_000.0 * 0.5);

        let cross_long = run(ClockBridge::CrossDomain, target * 2);
        let cross_short = run(ClockBridge::CrossDomain, 0);
        assert_eq!(cross_long, cross_short, "disciplined legs do not steer");
    }

    /// Depth follows jitter, within the policy's bounds.
    #[test]
    fn depth_target_grows_with_jitter_and_respects_bounds() {
        let policy = BridgePolicy::for_class(ClockBridge::Adaptive).unwrap();
        let depth_for = |jitter_us: f64| {
            let mut c = LegClock::new(policy, HZ);
            for (t, f) in sender(0.0, jitter_us, 500, 7) {
                c.observe(t, f, 0);
            }
            c.target_depth_frames()
        };
        let (d_quiet, d_mid, d_loud) = (depth_for(10.0), depth_for(3_000.0), depth_for(1_000_000.0));
        assert_eq!(d_quiet, policy.min_depth, "quiet link sits at the floor");
        assert!(d_mid > d_quiet && d_mid < policy.max_depth, "{d_mid}");
        assert_eq!(d_loud, policy.max_depth, "absurd jitter hits the ceiling, never beyond");
    }

    /// End to end through the real kernel: a sender 0.2 % fast (2000 ppm — a
    /// free-running USB interface against a Mac, well inside the Adaptive
    /// band) feeds 1 ms packets into a jitter queue; a consumer drains it at
    /// nominal rate through controller + rubato. Uncontrolled, the queue would
    /// grow by 48 000 × 0.002 × 20 s = 1920 frames (40 chunks). Controlled, it
    /// must stay within a few chunks of the depth target for the whole run,
    /// never underrun once primed, and the signal must come out intact.
    #[test]
    fn loopback_holds_the_buffer_against_a_fast_sender() {
        use crate::kernel::RubatoKernel;
        let policy = BridgePolicy::for_class(ClockBridge::Adaptive).unwrap();
        let chunk = FRAMES_PER_PKT as usize;
        let mut kernel = RubatoKernel::new(&policy, 1, chunk).unwrap();
        let mut clock = LegClock::new(policy, HZ);

        let ppm = 2_000.0;
        let seconds = 20.0;
        let packets = (seconds * 1000.0 * (1.0 + ppm / 1e6)) as usize;
        let arrivals = sender(ppm, 100.0, packets, 11);

        // Source signal: 1 kHz sine at the sender's own (fast) rate.
        let true_hz = HZ as f64 * (1.0 + ppm / 1e6);
        let mut phase = 0.0f64;
        let mut queue: VecDeque<f32> = VecDeque::new();
        let mut produced: u64 = 0;
        let mut max_fill = 0usize;
        let mut underruns = 0u32;
        let mut primed = false;
        // Output the consumer has been owed since priming; output owed before
        // that is not real demand (the leg was still filling).
        let mut owed_base: u64 = 0;
        let nominal_frames_at = |t_ns: u64| (t_ns as f64 * 1e-9 * HZ as f64) as u64;
        let mut tail: Vec<f32> = Vec::new();

        for (i, &(t_ns, cum)) in arrivals.iter().enumerate() {
            for _ in 0..chunk {
                queue.push_back((phase * std::f64::consts::TAU).sin() as f32);
                phase = (phase + 1_000.0 / true_hz).fract();
            }
            clock.drive(&mut kernel, t_ns, cum, queue.len() as u32);
            let target = clock.target_depth_frames() as usize;
            if !primed && queue.len() >= target {
                primed = true;
                owed_base = nominal_frames_at(t_ns);
            }
            if !primed {
                continue;
            }
            // Consumer: owes output at nominal rate since priming.
            let owed = nominal_frames_at(t_ns) - owed_base;
            while produced < owed {
                if queue.len() < chunk {
                    underruns += 1;
                    break;
                }
                let input: Vec<Vec<f32>> = vec![queue.drain(..chunk).collect()];
                let out = kernel.process(&input).unwrap();
                produced += out[0].len() as u64;
                if i + 1000 >= arrivals.len() {
                    tail.extend_from_slice(out[0]);
                }
            }
            if i > arrivals.len() / 4 {
                max_fill = max_fill.max(queue.len());
            }
        }

        let target = clock.target_depth_frames() as usize;
        assert!(primed);
        assert_eq!(underruns, 0, "a primed adaptive leg must never starve");
        assert!(
            max_fill <= target + 4 * chunk,
            "queue ran away: max fill {max_fill} vs target {target} (+4 chunks); drift est {:?} ppm",
            clock.drift_ppm()
        );
        assert!((clock.drift_ppm().unwrap() - ppm).abs() < 10.0, "controller tracked {:?} ppm", clock.drift_ppm());

        // The last second of output is still a full-scale sine.
        let peak = tail.iter().fold(0.0f32, |m, &x| m.max(x.abs()));
        assert!(peak > 0.95 && peak < 1.05, "output peak {peak}");
        let rms = (tail.iter().map(|&x| (x * x) as f64).sum::<f64>() / tail.len() as f64).sqrt();
        assert!((rms - std::f64::consts::FRAC_1_SQRT_2).abs() < 0.02, "output rms {rms} (expected 1/√2 for a sine)");
    }

    /// `drive` is observe + ratio + kernel push; the kernel sees every ratio.
    #[test]
    fn drive_pushes_each_ratio_into_the_kernel() {
        let mut clock = LegClock::new(BridgePolicy::for_class(ClockBridge::Adaptive).unwrap(), HZ);
        let mut kernel = Recorder(Vec::new());
        let obs = sender(100.0, 20.0, 5_000, 8);
        for &(t, f) in &obs {
            clock.drive(&mut kernel, t, f, clock.target_depth_frames());
        }
        assert_eq!(kernel.0.len(), obs.len());
        let last = *kernel.0.last().unwrap();
        assert!(((last - 1.0) * 1e6 - 100.0).abs() < 5.0, "{}", (last - 1.0) * 1e6);
    }
}
