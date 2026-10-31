//! The borrowed ASRC kernel: `rubato`'s asynchronous sinc resampler behind the
//! crate's [`Resampler`] trait (R010-F4 P2).
//!
//! Ratio convention bridge: [`LegClock`](crate::LegClock) reports *sender rate /
//! nominal* (`> 1` = the sender runs fast), while rubato's ratio is
//! *fs_out / fs_in*. Consuming a fast sender at nominal output therefore means
//! `fs_out / fs_in = 1 / r`; [`RubatoKernel::set_ratio`] does that inversion, so
//! the controller never has to know which way the kernel counts.
//!
//! Fixed-input mode (`FixedAsync::Input`): every [`process`](RubatoKernel::process)
//! call consumes exactly [`chunk_frames`](RubatoKernel::chunk_frames) input
//! frames (a packet's worth, by construction) and yields however many output
//! frames the current ratio implies — the natural shape for a jitter-buffer
//! consumer that drains one packet at a time.

use rubato::audioadapter_buffers::direct::SequentialSliceOfVecs;
use rubato::Resampler as RubatoResampler;
use rubato::{Adjustable, Async, FixedAsync, ResampleError, ResamplerConstructionError, SincInterpolationParameters, WindowFunction};

use crate::{BridgePolicy, Resampler};

/// rubato's async sinc resampler, sized for a leg's policy band.
pub struct RubatoKernel {
    inner: Async<f32>,
    channels: usize,
    chunk_frames: usize,
    /// Largest relative ratio the kernel was built to accept, so a ratio the
    /// controller hands us is clamped into it rather than rejected mid-stream.
    max_rel: f64,
    out: Vec<Vec<f32>>,
}

impl RubatoKernel {
    /// Build a kernel for `channels` of `chunk_frames`-frame input packets whose
    /// ratio may wander within `policy.max_ppm` (with 2× headroom so a clamped
    /// controller output is always representable).
    pub fn new(policy: &BridgePolicy, channels: usize, chunk_frames: usize) -> Result<Self, ResamplerConstructionError> {
        let max_rel = 1.0 + 2.0 * policy.max_ppm / 1e6;
        // 128-tap Blackman-Harris² sinc: rubato's documented quality/CPU middle
        // ground; the leg is ~8–16 ch (W001 §6) so CPU, not quality, is the
        // budget to watch.
        let params = SincInterpolationParameters::new(128, WindowFunction::BlackmanHarris2);
        let inner = Async::<f32>::new_sinc(1.0, max_rel, &params, chunk_frames, channels, FixedAsync::Input)?;
        let out_max = <Async<f32> as RubatoResampler<f32>>::output_frames_max(&inner);
        Ok(Self { inner, channels, chunk_frames, max_rel, out: vec![vec![0.0; out_max]; channels] })
    }

    /// Input frames each [`process`](Self::process) call consumes.
    pub fn chunk_frames(&self) -> usize {
        self.chunk_frames
    }

    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Resample one chunk. `input` is channel-sequential (`input[ch][frame]`),
    /// each channel at least [`chunk_frames`](Self::chunk_frames) long. Returns
    /// the output, channel-sequential, trimmed to the frames actually produced.
    pub fn process(&mut self, input: &[Vec<f32>]) -> Result<Vec<&[f32]>, ResampleError> {
        let frames = <Async<f32> as RubatoResampler<f32>>::input_frames_next(&self.inner);
        let out_frames = <Async<f32> as RubatoResampler<f32>>::output_frames_next(&self.inner);
        let adapter_in = SequentialSliceOfVecs::new(input, self.channels, frames)
            .map_err(|_| ResampleError::InsufficientInputBufferSize { expected: frames, actual: input.first().map_or(0, Vec::len) })?;
        let mut adapter_out = SequentialSliceOfVecs::new_mut(&mut self.out, self.channels, out_frames)
            .expect("out buffer is sized to output_frames_max");
        let (_, written) =
            <Async<f32> as RubatoResampler<f32>>::process_into_buffer(&mut self.inner, &adapter_in, &mut adapter_out, None)?;
        Ok(self.out.iter().map(|ch| &ch[..written]).collect())
    }
}

impl Resampler for RubatoKernel {
    fn set_ratio(&mut self, ratio: f64) {
        // Controller: sender/nominal. Kernel: out/in. Invert, then keep inside
        // the band the kernel was constructed for (the controller already clamps
        // to the policy band; this guards the 2× headroom, not the policy).
        let rel = (1.0 / ratio).clamp(1.0 / self.max_rel, self.max_rel);
        <Async<f32> as Adjustable<f32>>::set_resample_ratio_relative(&mut self.inner, rel, true)
            .expect("relative ratio clamped into the constructor's band");
    }
}
