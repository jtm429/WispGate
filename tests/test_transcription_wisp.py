from __future__ import annotations

import asyncio
import os
from pathlib import Path

from appserve import UploadedFile, WispAction, WispContext
from examples.transcription_wisp import (
    Diarizer,
    SherpaDiarizer,
    SpeakerSpan,
    TranscriptSpan,
    Transcriber,
    TranscriptionWisp,
    merge_spans,
)


class FakeTranscriber:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def transcribe(self, audio_path: str) -> list[TranscriptSpan]:
        self.paths.append(audio_path)
        return [TranscriptSpan(0.0, 1.0, "hello")]


class FakeDiarizer:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def diarize(self, audio_path: str) -> list[SpeakerSpan]:
        self.paths.append(audio_path)
        return [SpeakerSpan(0.0, 1.0, "speaker_a")]


def test_merge_assigns_speaker_by_timestamp_overlap() -> None:
    turns = merge_spans(
        [TranscriptSpan(0.0, 2.0, "hello")],
        [SpeakerSpan(0.0, 1.0, "speaker_a"), SpeakerSpan(1.0, 2.0, "speaker_b")],
    )
    assert turns[0].speaker in {"speaker_a", "speaker_b"}


def test_wisp_passes_same_complete_file_to_both_engines(tmp_path: Path) -> None:
    source = tmp_path / "episode.wav"
    source.write_bytes(b"complete recording")
    transcriber = FakeTranscriber()
    diarizer = FakeDiarizer()
    wisp = TranscriptionWisp(transcriber, diarizer)
    uploaded = UploadedFile("recording", "episode.wav", "audio/wav", source.stat().st_size, source)

    result = asyncio.run(wisp.action(WispAction({"type": "process"}, {"recording": uploaded}), WispContext("test-peer")))

    assert "speaker_a" in result["html"]
    assert transcriber.paths == diarizer.paths == [str(source)]


def test_duplicate_processing_request_is_rejected_while_locked(tmp_path: Path) -> None:
    source = tmp_path / "episode.wav"
    source.write_bytes(b"complete recording")
    wisp = TranscriptionWisp(FakeTranscriber(), FakeDiarizer())
    uploaded = UploadedFile("recording", "episode.wav", "audio/wav", source.stat().st_size, source)

    async def scenario() -> None:
        await wisp._processing_lock.acquire()
        try:
            result = await wisp.action(WispAction({"type": "process"}, {"recording": uploaded}), WispContext("test-peer"))
            assert "already being processed" in result["html"]
        finally:
            wisp._processing_lock.release()

    asyncio.run(scenario())


def test_transcription_wisp_turns_into_empty_response_for_empty_models(tmp_path: Path) -> None:
    source = tmp_path / "episode.wav"
    source.write_bytes(b"complete recording")

    class EmptyTranscriber:
        def transcribe(self, audio_path: str) -> list[TranscriptSpan]:
            return []

    class EmptyDiarizer:
        def diarize(self, audio_path: str) -> list[SpeakerSpan]:
            return []

    wisp = TranscriptionWisp(EmptyTranscriber(), EmptyDiarizer())
    uploaded = UploadedFile("recording", "episode.wav", "audio/wav", source.stat().st_size, source)
    result = asyncio.run(wisp.action(WispAction({"type": "process"}, {"recording": uploaded}), WispContext("test-peer")))
    assert "No speech turns found" in result["html"]


def test_sherpa_diarizer_uses_local_model_directory(tmp_path: Path) -> None:
    (tmp_path / "segmentation.onnx").write_bytes(b"segmentation")
    (tmp_path / "embedding.onnx").write_bytes(b"embedding")
    diarizer = SherpaDiarizer(tmp_path)
    assert diarizer.model_directory == tmp_path


def test_sherpa_diarizer_passes_only_samples_to_installed_process_api(tmp_path: Path) -> None:
    import soundfile as sf

    (tmp_path / "segmentation.onnx").write_bytes(b"segmentation")
    (tmp_path / "embedding.onnx").write_bytes(b"embedding")
    audio_path = tmp_path / "episode.wav"
    sf.write(audio_path, [0.0] * 160, 16_000)
    observed: dict[str, object] = {}

    class Segment:
        start = 0.0
        end = 0.01
        speaker = 0

    class FakeSherpaResult:
        def sort_by_start_time(self):
            return [Segment()]

    class FakeSherpaEngine:
        sample_rate = 16_000

        def process(self, samples: list[float]):
            observed["sample_count"] = len(samples)
            return FakeSherpaResult()

    diarizer = SherpaDiarizer(tmp_path)
    diarizer._diarizer = FakeSherpaEngine()

    result = diarizer.diarize(str(audio_path))

    assert observed == {"sample_count": 160}
    assert result == [SpeakerSpan(0.0, 0.01, "speaker_0")]
