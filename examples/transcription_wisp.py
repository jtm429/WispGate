"""Wisp for remote transcription and speaker diarization of complete recordings."""

from __future__ import annotations

import asyncio
import html
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

# Support direct imports when this module is run from examples/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from appserve import UploadedFile, Wisp, WispAction


@dataclass(frozen=True)
class TranscriptSpan:
    start: float
    end: float
    text: str


@dataclass(frozen=True)
class SpeakerSpan:
    start: float
    end: float
    speaker: str


@dataclass(frozen=True)
class HumanTurn:
    sequence: int
    speaker: str | None
    start: float
    end: float
    text: str


class Transcriber(Protocol):
    def transcribe(self, audio_path: str) -> list[TranscriptSpan]: ...


class Diarizer(Protocol):
    def diarize(self, audio_path: str) -> list[SpeakerSpan]: ...


class FasterWhisperTranscriber:
    """Complete-file ASR backend. The model is loaded lazily on first request."""

    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or os.getenv("BAKANEKO_ASR_MODEL", "large-v3")
        self._model: Any = None

    def transcribe(self, audio_path: str) -> list[TranscriptSpan]:
        try:
            from faster_whisper import WhisperModel
        except ImportError as exc:
            raise RuntimeError("Install faster-whisper to enable remote ASR") from exc
        if self._model is None:
            self._model = WhisperModel(
                self.model_name,
                device=os.getenv("BAKANEKO_ASR_DEVICE", "auto"),
                compute_type=os.getenv("BAKANEKO_ASR_COMPUTE_TYPE", "auto"),
            )
        segments, _info = self._model.transcribe(
            audio_path,
            beam_size=int(os.getenv("BAKANEKO_ASR_BEAM_SIZE", "5")),
            vad_filter=True,
            word_timestamps=False,
        )
        return [TranscriptSpan(float(segment.start), float(segment.end), segment.text.strip()) for segment in segments if segment.text.strip()]


class SherpaDiarizer:
    """Complete-file sherpa-onnx diarization using local, non-gated models."""

    def __init__(self, model_directory: str | Path | None = None) -> None:
        default_directory = Path(__file__).with_name("models") / "sherpa"
        self.model_directory = Path(model_directory or os.getenv("BAKANEKO_DIARIZATION_MODEL_DIR", default_directory))
        self._diarizer: Any = None

    def diarize(self, audio_path: str) -> list[SpeakerSpan]:
        try:
            import sherpa_onnx
            import soundfile as sf
        except ImportError as exc:
            raise RuntimeError("Install sherpa-onnx and soundfile to enable remote diarization") from exc
        segmentation = self.model_directory / "segmentation.onnx"
        embedding = self.model_directory / "embedding.onnx"
        if not segmentation.is_file() or not embedding.is_file():
            raise RuntimeError(f"Missing sherpa diarization models in {self.model_directory}")
        if self._diarizer is None:
            self._diarizer = sherpa_onnx.OfflineSpeakerDiarization(
                sherpa_onnx.OfflineSpeakerDiarizationConfig(
                    segmentation=sherpa_onnx.OfflineSpeakerSegmentationModelConfig(
                        pyannote=sherpa_onnx.OfflineSpeakerSegmentationPyannoteModelConfig(
                            model=str(segmentation), window_shift_ratio=0.1
                        ),
                        num_threads=2, provider="cpu",
                    ),
                    embedding=sherpa_onnx.SpeakerEmbeddingExtractorConfig(
                        model=str(embedding), num_threads=2, provider="cpu",
                    ),
                    clustering=sherpa_onnx.FastClusteringConfig(num_clusters=-1, threshold=0.5),
                    min_duration_on=0.2, min_duration_off=0.5,
                )
            )
        samples, sample_rate = sf.read(audio_path, dtype="float32", always_2d=False)
        expected_sample_rate = int(self._diarizer.sample_rate)
        if int(sample_rate) != expected_sample_rate:
            raise ValueError(
                f"Diarization requires {expected_sample_rate} Hz audio, got {int(sample_rate)} Hz"
            )
        if getattr(samples, "ndim", 1) > 1:
            samples = samples.mean(axis=1)
        result = self._diarizer.process(samples.tolist())
        return [
            SpeakerSpan(float(item.start), float(item.end), f"speaker_{item.speaker}")
            for item in result.sort_by_start_time()
        ]


def merge_spans(transcript: list[TranscriptSpan], speakers: list[SpeakerSpan]) -> list[HumanTurn]:
    """Assign complete-file ASR spans to overlapping diarization spans."""
    turns: list[HumanTurn] = []
    for span in sorted(transcript, key=lambda item: item.start):
        overlaps = [speaker for speaker in speakers if min(span.end, speaker.end) > max(span.start, speaker.start)]
        speaker = max(
            overlaps,
            key=lambda item: (min(span.end, item.end) - max(span.start, item.start), -abs((span.start + span.end) / 2 - (item.start + item.end) / 2)),
            default=None,
        )
        turns.append(HumanTurn(len(turns), speaker.speaker if speaker else None, span.start, span.end, span.text))
    return turns


def render_form(message: str = "") -> dict[str, str]:
    notice = f"<p role='alert'>{html.escape(message)}</p>" if message else ""
    return {
        "content_type": "text/html",
        "html": f"""
        <main style='min-height:100vh;display:flex;align-items:center;justify-content:center'>
          <form onsubmit='event.preventDefault(); WispGate.submitForm(this, {{type:"process"}})' enctype='multipart/form-data' style='display:flex;flex-direction:column;gap:12px;width:min(90vw,32rem)'>
            <label for='recording'>Complete recording</label>
            <input id='recording' name='recording' type='file' accept='audio/*,.wav,.mp3,.m4a' required>
            <button type='submit'>Transcribe and diarize</button>
            {notice}
          </form>
        </main>
        """.strip(),
    }


def render_result(turns: list[HumanTurn]) -> dict[str, str]:
    rows = "".join(
        f"<article><strong>{html.escape(turn.speaker or 'unknown speaker')}</strong> "
        f"<time>{turn.start:.2f}–{turn.end:.2f}s</time><p>{html.escape(turn.text)}</p></article>"
        for turn in turns
    )
    return {"content_type": "text/html", "html": f"<main><h1>Transcript</h1>{rows or '<p>No speech turns found.</p>'}</main>"}


class TranscriptionWisp:
    def __init__(self, transcriber: Transcriber | None = None, diarizer: Diarizer | None = None) -> None:
        self.log = logging.getLogger("bakaneko.transcription_wisp")
        self.transcriber = transcriber or FasterWhisperTranscriber()
        self.diarizer = diarizer or SherpaDiarizer()
        self._processing_lock = asyncio.Lock()
        self.current: dict[str, str] = render_form()

    def state(self) -> dict[str, str]:
        return self.current

    async def _process(self, recording: UploadedFile) -> dict[str, str]:
        self.log.info("received complete recording name=%s bytes=%s path=%s", recording.name, recording.size, recording.path)
        if recording.size <= 0:
            return render_form("Choose a non-empty recording.")
        if recording.size > 2 * 1024 * 1024 * 1024:
            return render_form("Recordings must be 2 GiB or smaller.")
        # Both engines receive this same complete temporary file. No speaker slicing occurs.
        self.log.info("starting complete-file ASR and diarization")
        async def run_asr() -> list[TranscriptSpan]:
            self.log.info("ASR started")
            result = await asyncio.to_thread(self.transcriber.transcribe, str(recording.path))
            self.log.info("ASR finished spans=%s", len(result))
            return result
        async def run_diarization() -> list[SpeakerSpan]:
            self.log.info("diarization started")
            result = await asyncio.to_thread(self.diarizer.diarize, str(recording.path))
            self.log.info("diarization finished spans=%s speakers=%s", len(result), len({item.speaker for item in result}))
            return result
        transcript, speakers = await asyncio.gather(run_asr(), run_diarization())
        turns = merge_spans(transcript, speakers)
        self.log.info("merged response turns=%s", len(turns))
        return render_result(turns)

    async def action(self, action: WispAction | dict[str, Any]) -> dict[str, str]:
        if action.get("type") != "process":
            return self.current
        files = getattr(action, "files", {})
        recording = files.get("recording")
        if not isinstance(recording, UploadedFile):
            self.current = render_form("Upload one complete audio recording.")
            return self.current
        if self._processing_lock.locked():
            self.log.warning("duplicate transcription request ignored while processing")
            return render_form("A recording is already being processed. Please wait for the current result.")
        try:
            async with self._processing_lock:
                self.current = await self._process(recording)
        except Exception as exc:
            self.log.exception("processing failed")
            self.current = render_form(f"Processing failed: {exc}")
        return self.current

    def as_wisp(self) -> Wisp:
        return Wisp(
            "transcription-diarization",
            "Transcription and diarization",
            "Transcribes and separates speakers from one complete audio recording",
            self.state,
            self.action,
        )
