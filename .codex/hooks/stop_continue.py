#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STORIES_PATH = Path("tasks/stories.json")
PROMISE_PREFIX = "<promise>"
PROMISE_SUFFIX = "</promise>"
COMPLETION_TYPE = "STORY_COMPLETE"


@dataclass(frozen=True)
class StopPayload:
    cwd: Path
    last_assistant_message: str


@dataclass(frozen=True)
class StoryState:
    identifier: str | None
    passes: bool
    sprint: int | None
    priority: int | None
    order: int


@dataclass(frozen=True)
class StoriesState:
    stories: list[StoryState]
    checkpoint_enabled: bool


@dataclass(frozen=True)
class HookDecision:
    prompt: str


@dataclass(frozen=True)
class CompletionEvent:
    story_id: str | None


def load_payload() -> StopPayload:
    raw_payload = json.load(sys.stdin)
    cwd = Path(raw_payload["cwd"]).resolve()
    return StopPayload(
        cwd=cwd,
        last_assistant_message=str(raw_payload.get("last_assistant_message") or ""),
    )


def detect_repo_root(cwd: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    return Path(result.stdout.strip()).resolve()


def read_stories_data(stories_path: Path) -> tuple[list[dict[str, Any]], bool]:
    if not stories_path.exists():
        return [], True

    data = json.loads(stories_path.read_text())
    checkpoint_enabled = True

    if isinstance(data, list):
        stories = data
    elif isinstance(data, dict):
        checkpoint_enabled = parse_checkpoint_enabled(data.get("sprintConfig"))
        for key in ("userStories", "stories", "items"):
            value = data.get(key)
            if isinstance(value, list):
                stories = value
                break
        else:
            stories = []
    else:
        stories = []

    filtered_stories = [story for story in stories if isinstance(story, dict)]
    return filtered_stories, checkpoint_enabled


def parse_checkpoint_enabled(value: Any) -> bool:
    if not isinstance(value, dict):
        return True

    enabled = value.get("checkpointEnabled")
    if isinstance(enabled, bool):
        return enabled

    return True


def story_id(story: dict[str, Any], index: int) -> str | None:
    for key in ("id", "storyId", "story_id", "key"):
        value = story.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    title = story.get("title")
    if isinstance(title, str) and title.strip():
        return f"story #{index + 1} ({title.strip()})"

    return None


def parse_sprint(value: Any) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def parse_priority(value: Any) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def load_stories_state(stories_path: Path) -> StoriesState:
    raw_stories, checkpoint_enabled = read_stories_data(stories_path)
    stories = [
        StoryState(
            identifier=story_id(story, index),
            passes=story.get("passes") is True,
            sprint=parse_sprint(story.get("sprint")),
            priority=parse_priority(story.get("priority")),
            order=index,
        )
        for index, story in enumerate(raw_stories)
    ]
    return StoriesState(stories=stories, checkpoint_enabled=checkpoint_enabled)


def has_any_sprint(stories: list[StoryState]) -> bool:
    return any(story.sprint is not None for story in stories)


def ordered_stories(stories: list[StoryState]) -> list[StoryState]:
    return sorted(
        stories,
        key=lambda story: (
            story.priority if story.priority is not None else sys.maxsize,
            story.order,
        ),
    )


def first_unfinished_story(
    stories: list[StoryState], *, sprint: int | None = None
) -> StoryState | None:
    for story in ordered_stories(stories):
        if story.passes or story.identifier is None:
            continue
        if sprint is not None and story.sprint != sprint:
            continue
        return story
    return None


def find_story_by_id(stories: list[StoryState], story_id: str) -> StoryState | None:
    for story in stories:
        if story.identifier == story_id:
            return story
    return None


def extract_completion_event(message: str) -> CompletionEvent | None:
    for line in reversed(message.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith(PROMISE_PREFIX) or not stripped.endswith(PROMISE_SUFFIX):
            return None

        content = stripped.removeprefix(PROMISE_PREFIX).removesuffix(PROMISE_SUFFIX).strip()
        if content == COMPLETION_TYPE:
            return CompletionEvent(story_id=None)

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict) or data.get("type") != COMPLETION_TYPE:
            return None

        story_id = data.get("storyId")
        if isinstance(story_id, str) and story_id.strip():
            return CompletionEvent(story_id=story_id.strip())
        return None

    return None


def build_prompt(next_story: str) -> str:
    return f"$story-loop {next_story}"


def build_checkpoint_prompt(completed_sprint: int) -> str:
    return f"$sprint-checkpoint {completed_sprint}"


def should_checkpoint_after_story(
    stories: list[StoryState], completed_story: StoryState
) -> bool:
    if completed_story.sprint is None:
        return False

    if first_unfinished_story(stories, sprint=completed_story.sprint) is not None:
        return False

    return any(
        not story.passes and story.identifier is not None and story.sprint != completed_story.sprint
        for story in stories
    )


def decide_next_action(stories_path: Path, completion_event: CompletionEvent) -> HookDecision | None:
    stories_state = load_stories_state(stories_path)
    stories = stories_state.stories

    if completion_event.story_id is not None:
        completed_story = find_story_by_id(stories, completion_event.story_id)
        if (
            completed_story is not None
            and stories_state.checkpoint_enabled
            and has_any_sprint(stories)
            and should_checkpoint_after_story(stories, completed_story)
        ):
            return HookDecision(build_checkpoint_prompt(completed_story.sprint))

    next_story = first_unfinished_story(stories)
    if next_story is None or next_story.identifier is None:
        return None

    return HookDecision(build_prompt(next_story.identifier))


def main() -> int:
    payload = load_payload()
    repo_root = detect_repo_root(payload.cwd)
    if repo_root is None:
        return 0

    completion_event = extract_completion_event(payload.last_assistant_message)
    if completion_event is None:
        return 0

    decision = decide_next_action(repo_root / STORIES_PATH, completion_event)
    if decision is None:
        return 0

    print(json.dumps({"decision": "block", "reason": decision.prompt}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
