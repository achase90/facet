"""Tests for api/config_writes.py — the locked category priority writer."""

import errno
import json
import os
import shutil
import logging
import stat
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest
from fastapi import HTTPException

import config_resolve

from api import config as api_config
from api.auth import _is_hashed, upgrade_legacy_password
from api.config import CONFIG_WRITE_LOCK, write_user_config
from api.config_writes import (
    BACKUP_FILE_MODE,
    MAX_CONFIG_BACKUPS,
    update_category_priorities,
    update_category_weights,
    update_scoring_context,
    write_owner_only_backup,
)
from config.scoring_config import ScoringConfig

REPO_CONFIG_PATH = Path(config_resolve.defaults_path())


@pytest.fixture
def config_copy(tmp_path):
    """A private, disposable copy of the real scoring_config.json."""
    dest = tmp_path / "scoring_config.json"
    shutil.copy2(REPO_CONFIG_PATH, dest)
    return dest


def _non_default_names(config_path):
    cfg = ScoringConfig(str(config_path), validate=False)
    return [c["name"] for c in cfg.get_categories() if c["name"] != "default"]


def _mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


_GROUP_WRITABLE_MODE = 0o664
_SENSITIVE_CONFIG = '{"viewer": {"password": "plaintext-pw"}, "share_secret": "aaaa"}'


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits do not apply on Windows")
class TestOwnerOnlyBackupPrimitive:
    """H2/H3: a config backup carries every secret scoring_config.json does.

    ``shutil.copy2`` — what every backup writer here and in ``api.auth`` used
    to call — copies the MODE along with the bytes, so each one landed at the
    config's own 0664 holding ``share_secret``, ``users.*.password_hash`` and,
    for the password upgrade, the plaintext password just typed. Unlike the
    config itself, whose group read bit a co-deployed CLI needs, a backup has
    no reader but its owner.
    """

    def _sensitive_source(self, tmp_path):
        source = tmp_path / "scoring_config.json"
        source.write_text(_SENSITIVE_CONFIG)
        os.chmod(source, _GROUP_WRITABLE_MODE)
        return source

    def test_the_backup_is_owner_only_whatever_the_source_mode(self, tmp_path):
        source = self._sensitive_source(tmp_path)

        backup = write_owner_only_backup(source, tmp_path / "scoring_config.json.backup")

        assert _mode_of(backup) == BACKUP_FILE_MODE
        assert Path(backup).read_text() == _SENSITIVE_CONFIG

    def test_the_source_mode_is_left_alone(self, tmp_path):
        """Only the copy is restricted: the config keeps whatever it had."""
        source = self._sensitive_source(tmp_path)

        write_owner_only_backup(source, tmp_path / "scoring_config.json.backup")

        assert _mode_of(source) == _GROUP_WRITABLE_MODE

    def test_the_destination_is_created_owner_only(self, tmp_path):
        """Created at 0600, not created-then-chmodded: an ``os.open`` mode
        argument leaves no window, a following ``chmod`` does."""
        source = self._sensitive_source(tmp_path)
        backup_path = tmp_path / "scoring_config.json.backup"
        creations = []
        real_open = os.open

        def _recording_open(path, flags, mode=0o777, **kwargs):
            if str(path) == str(backup_path):
                creations.append(mode)
            return real_open(path, flags, mode, **kwargs)

        with mock.patch("api.config_writes.os.open", _recording_open):
            write_owner_only_backup(source, backup_path)

        assert creations == [BACKUP_FILE_MODE]

    def test_a_reused_backup_name_is_tightened_before_it_holds_anything(self, tmp_path):
        """The creation mode does nothing when the name already exists.

        Every install that ran an older Facet has exactly that: a
        ``scoring_config.json.backup`` sitting at 0664. The bytes must not land
        in it at that mode and be tightened afterwards, so the mode is asserted
        at the moment the first byte is written — the window a plain ``chmod``
        after the copy leaves open.
        """
        source = self._sensitive_source(tmp_path)
        backup_path = tmp_path / "scoring_config.json.backup"
        backup_path.write_text("stale")
        os.chmod(backup_path, _GROUP_WRITABLE_MODE)
        modes_while_writing = []
        real_copyfileobj = shutil.copyfileobj

        def _recording_copyfileobj(source_file, destination_file, *args, **kwargs):
            modes_while_writing.append(_mode_of(backup_path))
            return real_copyfileobj(source_file, destination_file, *args, **kwargs)

        with mock.patch("api.config_writes.shutil.copyfileobj", _recording_copyfileobj):
            write_owner_only_backup(source, backup_path)

        assert modes_while_writing == [BACKUP_FILE_MODE]
        assert _mode_of(backup_path) == BACKUP_FILE_MODE
        assert backup_path.read_text() == _SENSITIVE_CONFIG

    def test_timestamped_backups_of_a_real_write_are_owner_only(self, config_copy):
        """The end-to-end shape: this checkout accumulated nine 0664 backups
        holding a 64-character ``share_secret`` this way."""
        os.chmod(config_copy, _GROUP_WRITABLE_MODE)

        backup_path = update_scoring_context(config_copy, "action_stage", ["wildlife"], [])

        assert _mode_of(backup_path) == BACKUP_FILE_MODE
        assert _mode_of(config_copy) == _GROUP_WRITABLE_MODE


class TestUpdateCategoryPriorities:
    """update_category_priorities permutes existing priority values onto a new order."""

    def test_order_matches_request(self, config_copy):
        new_order = list(reversed(_non_default_names(config_copy)))

        update_category_priorities(config_copy, new_order)

        cfg = ScoringConfig(str(config_copy), validate=False)
        result_names = [c["name"] for c in cfg.get_categories() if c["name"] != "default"]
        assert result_names == new_order

    def test_priority_multiset_unchanged(self, config_copy):
        before = ScoringConfig(str(config_copy), validate=False)
        before_priorities = sorted(c["priority"] for c in before.get_categories() if c["name"] != "default")
        new_order = list(reversed(_non_default_names(config_copy)))

        update_category_priorities(config_copy, new_order)

        after = ScoringConfig(str(config_copy), validate=False)
        after_priorities = sorted(c["priority"] for c in after.get_categories() if c["name"] != "default")
        assert after_priorities == before_priorities

    def test_default_priority_untouched(self, config_copy):
        before = ScoringConfig(str(config_copy), validate=False)
        default_priority_before = before.get_category_config("default")["priority"]
        new_order = list(reversed(_non_default_names(config_copy)))

        update_category_priorities(config_copy, new_order)

        after = ScoringConfig(str(config_copy), validate=False)
        assert after.get_category_config("default")["priority"] == default_priority_before
        assert default_priority_before == 999

    def test_validate_categories_clean_after_reorder(self, config_copy):
        new_order = list(reversed(_non_default_names(config_copy)))

        update_category_priorities(config_copy, new_order)

        cfg = ScoringConfig(str(config_copy), validate=False)
        ok, issues = cfg.validate_categories(verbose=False)
        assert ok is True
        assert issues == []

    def test_backup_file_is_written(self, config_copy):
        original_contents = config_copy.read_text()
        new_order = list(reversed(_non_default_names(config_copy)))

        backup_path = update_category_priorities(config_copy, new_order)

        assert backup_path is not None
        assert Path(backup_path).read_text() == original_contents

    def test_missing_category_raises_400(self, config_copy):
        order = _non_default_names(config_copy)[:-1]

        with pytest.raises(HTTPException) as exc_info:
            update_category_priorities(config_copy, order)
        assert exc_info.value.status_code == 400
        assert "missing" in exc_info.value.detail.lower()

    def test_unknown_category_raises_400(self, config_copy):
        order = _non_default_names(config_copy) + ["not_a_real_category"]

        with pytest.raises(HTTPException) as exc_info:
            update_category_priorities(config_copy, order)
        assert exc_info.value.status_code == 400
        assert "unknown" in exc_info.value.detail.lower()

    def test_duplicate_category_raises_400(self, config_copy):
        order = _non_default_names(config_copy)
        order[1] = order[0]

        with pytest.raises(HTTPException) as exc_info:
            update_category_priorities(config_copy, order)
        assert exc_info.value.status_code == 400
        assert "duplicate" in exc_info.value.detail.lower()

    def test_invalid_order_leaves_the_file_untouched(self, config_copy):
        original_contents = config_copy.read_text()
        order = _non_default_names(config_copy)[:-1]

        with pytest.raises(HTTPException):
            update_category_priorities(config_copy, order)
        assert config_copy.read_text() == original_contents

    def test_default_in_submitted_order_is_ignored(self, config_copy):
        """DEFECT 5 regression: GET includes 'default' in the evaluation
        order it returns, but POST's validation excludes it from the current
        names -- echoing GET's output back verbatim used to 400 as an
        'unknown category'. 'default' is pinned last regardless, so it must
        be accepted and ignored rather than rejected."""
        reversed_order = list(reversed(_non_default_names(config_copy)))
        order_with_default = reversed_order + ["default"]

        update_category_priorities(config_copy, order_with_default)

        cfg = ScoringConfig(str(config_copy), validate=False)
        result_names = [c["name"] for c in cfg.get_categories() if c["name"] != "default"]
        assert result_names == reversed_order

    def test_missing_priority_is_healed_instead_of_crashing_or_blocking(self, config_copy):
        """DEFECT M2/M3 regression: a category with a None priority previously
        crashed ``sorted()`` with an opaque TypeError, and a later fix turned
        that into a hard 400 -- which left a hand-edited config with no
        in-app way to fix it, since this endpoint is the only priority
        writer. ``validate_categories`` tolerates a missing priority as a
        logged issue, not a hard error, so this endpoint must agree: heal it
        and still honor the requested order."""
        data = json.loads(config_copy.read_text())
        target = next(c for c in data["categories"] if c["name"] != "default")
        del target["priority"]
        config_copy.write_text(json.dumps(data))

        order = _non_default_names(config_copy)

        update_category_priorities(config_copy, order)

        cfg = ScoringConfig(str(config_copy), validate=False)
        result_names = [c["name"] for c in cfg.get_categories() if c["name"] != "default"]
        assert result_names == order
        ok, issues = cfg.validate_categories(verbose=False)
        assert ok is True
        assert issues == []

    def test_duplicate_existing_priority_is_healed_instead_of_silently_misordering(self, config_copy):
        """DEFECT M2/M3 regression: the docstring once claimed priority
        uniqueness is 'guaranteed by construction', which was false -- the
        multiset of existing priorities was preserved verbatim, so a
        pre-existing collision (e.g. 'astro' colliding with 'art') made a
        full reversal return 200 OK while silently producing the wrong
        order. A later fix hard-rejected this instead, which left the
        Priorities tab permanently dead for a config it can't self-repair.
        Heal the collision (assign a fresh value past the current maximum)
        and still honor the requested order."""
        data = json.loads(config_copy.read_text())
        non_default = [c for c in data["categories"] if c["name"] != "default"]
        non_default[1]["priority"] = non_default[0]["priority"]
        config_copy.write_text(json.dumps(data))

        order = list(reversed(_non_default_names(config_copy)))

        update_category_priorities(config_copy, order)

        cfg = ScoringConfig(str(config_copy), validate=False)
        result_names = [c["name"] for c in cfg.get_categories() if c["name"] != "default"]
        assert result_names == order
        ok, issues = cfg.validate_categories(verbose=False)
        assert ok is True
        assert issues == []


def _raising_get_db():
    """A get_db stand-in for tests that don't need the best-effort weight
    snapshot: record_category_snapshot swallows any exception from get_db()
    and just logs a warning, so this keeps these tests from needing a real DB."""
    raise RuntimeError("no db needed for this test")


class TestUpdateCategoryWeightsBackupPruning:
    """DEBT A5#3: update_category_weights(backup=True) was the only writer
    passing prune=False to backup_config, so modifier/filter edits
    accumulated ~88KB backups unbounded. It must prune like every other
    config-backup writer (update_category_priorities, update_scoring_context)."""

    def test_backup_prunes_old_files_to_the_shared_limit(self, config_copy):
        config_path = str(config_copy)
        directory = os.path.dirname(config_path)
        prefix = os.path.basename(config_path) + ".backup."
        for i in range(MAX_CONFIG_BACKUPS + 5):
            shutil.copy2(config_path, os.path.join(directory, f"{prefix}stale{i:03d}"))
        backups_before = [f for f in os.listdir(directory) if f.startswith(prefix)]
        assert len(backups_before) > MAX_CONFIG_BACKUPS

        category = _non_default_names(config_copy)[0]
        update_category_weights(
            config_path, category, "test:prune", _raising_get_db,
            not_found_detail="missing",
            modifiers={"bonus": 0.1},
            backup=True,
        )

        backups_after = [f for f in os.listdir(directory) if f.startswith(prefix)]
        assert len(backups_after) <= MAX_CONFIG_BACKUPS


def _context(config_path, name):
    return ScoringConfig(str(config_path), validate=False).get_scoring_contexts()[name]


def _effective_order(config_path, name):
    cfg = ScoringConfig(str(config_path), validate=False)
    return [cat_name for cat_name, _ in cfg.resolve_context_order(name)]


class TestUpdateScoringContext:
    """update_scoring_context rewrites one context's promote/excluded delta."""

    CONTEXT = "action_stage"

    def test_promote_and_excluded_are_persisted(self, config_copy):
        update_scoring_context(config_copy, self.CONTEXT, ["wildlife", "sports"], ["macro"])

        context = _context(config_copy, self.CONTEXT)
        assert context["promote"] == ["wildlife", "sports"]
        assert context["excluded"] == ["macro"]

    def test_label_key_and_suggested_moments_are_preserved(self, config_copy):
        before = _context(config_copy, self.CONTEXT)

        update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])

        after = _context(config_copy, self.CONTEXT)
        assert after["label_key"] == before["label_key"]
        assert after["suggest_from_moments"] == before["suggest_from_moments"]

    def test_other_contexts_are_untouched(self, config_copy):
        before = _context(config_copy, "wildlife")

        update_scoring_context(config_copy, self.CONTEXT, ["macro"], [])

        assert _context(config_copy, "wildlife") == before

    def test_resolve_context_order_reflects_the_new_delta(self, config_copy):
        update_scoring_context(config_copy, self.CONTEXT, ["wildlife", "sports"], ["silhouette", "macro"])

        order = _effective_order(config_copy, self.CONTEXT)
        assert order[:2] == ["wildlife", "sports"]
        assert "silhouette" not in order
        assert "macro" not in order
        assert order[-1] == "default"

    def test_non_promoted_categories_keep_the_global_order(self, config_copy):
        """The delta model's whole point: only the promoted head moves."""
        promoted = ["wildlife", "sports"]
        global_rest = [name for name in _non_default_names(config_copy) if name not in promoted]

        update_scoring_context(config_copy, self.CONTEXT, promoted, [])

        assert _effective_order(config_copy, self.CONTEXT) == promoted + global_rest + ["default"]

    def test_empty_delta_matches_the_plain_priority_order(self, config_copy):
        update_scoring_context(config_copy, self.CONTEXT, [], [])

        assert _effective_order(config_copy, self.CONTEXT) == _non_default_names(config_copy) + ["default"]

    def test_validate_categories_clean_after_write(self, config_copy):
        update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], ["macro"])

        ok, issues = ScoringConfig(str(config_copy), validate=False).validate_categories(verbose=False)
        assert ok is True
        assert issues == []

    def test_backup_file_is_written(self, config_copy):
        original_contents = config_copy.read_text()

        backup_path = update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])

        assert backup_path is not None
        assert Path(backup_path).read_text() == original_contents

    def test_unknown_context_raises_404(self, config_copy):
        """An unknown named resource is a 404, matching how the sibling
        ``update_category_weights`` answers a category that isn't configured.
        The 400s below stay 400s: those are bodies that cannot be applied."""
        with pytest.raises(HTTPException) as exc_info:
            update_scoring_context(config_copy, "not_a_real_context", [], [])
        assert exc_info.value.status_code == 404
        assert "not_a_real_context" in exc_info.value.detail

    def test_unknown_promoted_category_raises_400(self, config_copy):
        with pytest.raises(HTTPException) as exc_info:
            update_scoring_context(config_copy, self.CONTEXT, ["not_a_real_category"], [])
        assert exc_info.value.status_code == 400
        assert "not_a_real_category" in exc_info.value.detail
        assert "promote" in exc_info.value.detail

    def test_unknown_excluded_category_raises_400(self, config_copy):
        with pytest.raises(HTTPException) as exc_info:
            update_scoring_context(config_copy, self.CONTEXT, [], ["not_a_real_category"])
        assert exc_info.value.status_code == 400
        assert "not_a_real_category" in exc_info.value.detail
        assert "excluded" in exc_info.value.detail

    def test_default_category_in_promote_raises_400(self, config_copy):
        with pytest.raises(HTTPException) as exc_info:
            update_scoring_context(config_copy, self.CONTEXT, ["default"], [])
        assert exc_info.value.status_code == 400
        assert "default" in exc_info.value.detail

    def test_default_category_in_excluded_raises_400(self, config_copy):
        with pytest.raises(HTTPException) as exc_info:
            update_scoring_context(config_copy, self.CONTEXT, [], ["default"])
        assert exc_info.value.status_code == 400
        assert "default" in exc_info.value.detail

    def test_duplicate_promoted_category_raises_400(self, config_copy):
        with pytest.raises(HTTPException) as exc_info:
            update_scoring_context(config_copy, self.CONTEXT, ["wildlife", "wildlife"], [])
        assert exc_info.value.status_code == 400
        assert "wildlife" in exc_info.value.detail
        assert "uplicate" in exc_info.value.detail

    def test_rejected_write_leaves_the_file_untouched(self, config_copy):
        original_contents = config_copy.read_text()

        with pytest.raises(HTTPException):
            update_scoring_context(config_copy, self.CONTEXT, ["not_a_real_category"], [])
        assert config_copy.read_text() == original_contents

    def test_category_in_both_lists_is_accepted_and_excluded_wins(self, config_copy):
        """Documented behaviour, preserved rather than rejected: a name in both
        lists is dropped from the order entirely."""
        update_scoring_context(config_copy, self.CONTEXT, ["wildlife", "macro"], ["macro"])

        context = _context(config_copy, self.CONTEXT)
        assert context["promote"] == ["wildlife", "macro"]
        assert context["excluded"] == ["macro"]
        assert "macro" not in _effective_order(config_copy, self.CONTEXT)

    def test_duplicate_exclusions_are_collapsed(self, config_copy):
        update_scoring_context(config_copy, self.CONTEXT, [], ["macro", "macro"])

        assert _context(config_copy, self.CONTEXT)["excluded"] == ["macro"]

    def test_malformed_context_entry_is_healed_instead_of_crashing(self, config_copy):
        """A hand-edited config can leave a context as a list or string;
        ``resolve_context_order`` tolerates that, so the writer must too rather
        than 500ing on item assignment.

        Only promote/excluded are asserted. The healed entry resolves over the
        shipped context, so it keeps that context's ``label_key`` and
        ``suggest_from_moments`` rather than losing them to the repair — which
        is the point of resolving over defaults, and better than the bare
        two-key dict a hand-healed file used to be left with.
        """
        data = json.loads(config_copy.read_text())
        data["scoring_contexts"][self.CONTEXT] = ["broken"]
        config_copy.write_text(json.dumps(data))

        update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])

        healed = _context(config_copy, self.CONTEXT)
        assert isinstance(healed, dict)
        assert healed["promote"] == ["wildlife"]
        assert healed["excluded"] == []

    def test_concurrent_context_writes_never_corrupt_the_file(self, config_copy):
        deltas = [(["wildlife"], ["macro"]), (["sports"], [])]

        def _write(delta):
            update_scoring_context(config_copy, self.CONTEXT, *delta)

        threads = [threading.Thread(target=_write, args=(deltas[i % 2],)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ok, issues = ScoringConfig(str(config_copy), validate=False).validate_categories(verbose=False)
        assert ok is True
        assert issues == []


class _SameSecondClock:
    """A clock whose successive readings differ only below the second."""

    def __init__(self):
        self._readings = 0

    def now(self):
        self._readings += 1
        return datetime(2026, 8, 9, 12, 0, 0, self._readings * 1000)


class TestAtomicConfigWrite:
    """The config writer must not change the file's permissions or lose data."""

    CONTEXT = "action_stage"
    GROUP_READABLE_MODE = 0o664
    OWNER_ONLY_MODE = 0o600

    def _mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    @pytest.mark.skipif(sys.platform == 'win32', reason="POSIX chmod permission bits do not apply on Windows")
    @pytest.mark.parametrize("mode", [GROUP_READABLE_MODE, OWNER_ONLY_MODE])
    def test_existing_permissions_are_preserved(self, config_copy, mode):
        """``tempfile.mkstemp`` creates its file 0600, so an unfixed writer
        silently locked a co-deployed CLI out of the config it shares."""
        os.chmod(config_copy, mode)

        update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])

        assert self._mode(config_copy) == mode

    @pytest.mark.skipif(sys.platform == 'win32', reason="POSIX directory fsync is not supported on Windows")
    def test_payload_is_fsynced_before_the_rename(self, config_copy):
        """Rename-atomic is not crash-durable: without the flush the rename can
        land while the replacement's bytes are still only in the page cache."""
        calls = []
        real_fsync, real_replace = os.fsync, os.replace

        def _record_fsync(fd):
            calls.append("fsync")
            return real_fsync(fd)

        def _record_replace(src, dst):
            calls.append("replace")
            return real_replace(src, dst)

        with mock.patch("os.fsync", _record_fsync), mock.patch("os.replace", _record_replace):
            update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])

        assert calls == ["fsync", "replace", "fsync"]

    def test_two_writes_in_one_second_keep_distinct_backups(self, config_copy):
        """A second-granular stamp made the second save overwrite the first
        backup, so the ``backup`` path returned no longer held what the caller
        was promised."""
        first_contents = config_copy.read_text()

        with mock.patch("api.config_writes.datetime", _SameSecondClock()):
            first_backup = update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])
            second_contents = config_copy.read_text()
            second_backup = update_scoring_context(config_copy, self.CONTEXT, ["sports"], [])

        assert first_backup != second_backup
        assert Path(first_backup).read_text() == first_contents
        assert Path(second_backup).read_text() == second_contents


class _ForeignOwner:
    """The destination's real ``lstat``, wearing a uid and gid that are not ours.

    The ownership route only engages when the staged copy and the destination
    differ in ``(st_uid, st_gid)``, and an unprivileged test cannot create a file
    owned by anybody else. Faking the ANSWER rather than the file keeps every
    other field real — ``st_ino`` and ``st_dev`` above all, which the in-place
    route re-checks the opened descriptor against and would otherwise refuse.
    """

    def __init__(self, real):
        self._real = real
        self.st_uid = real.st_uid + 1
        self.st_gid = real.st_gid + 1

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def foreign_destination(monkeypatch):
    """Report the config as belonging to another account, identity untouched."""
    real_identity = config_resolve._destination_identity

    def _foreign(path):
        info = real_identity(path)
        return info if info is None else _ForeignOwner(info)

    monkeypatch.setattr(config_resolve, "_destination_identity", _foreign)


@pytest.fixture
def denied_chown(monkeypatch):
    """Refuse every chown the way a rootless container's kernel does."""
    def _refuse(*args, **kwargs):
        # Constructed with TWO arguments so that ``errno`` is EPERM rather than
        # None. A bare PermissionError("nope") carries errno None, which the
        # writer re-raises instead of downgrading — the test would still pass,
        # but through the "this is a bug, not a denial" branch, proving nothing.
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "chown", _refuse)


# os.geteuid does not exist on Windows and skipif decorators evaluate at import
# time, so it is read the same guarded way tests/test_api_config.py reads it.
_IS_ROOT = os.geteuid() == 0 if hasattr(os, "geteuid") else False
_NOBODY = 65534


@pytest.mark.skipif(sys.platform == 'win32',
                    reason="POSIX ownership, O_NOFOLLOW and inode identity have no Windows analogue")
class TestOwnershipPreservingCommit:
    """``os.replace`` commits into a NEW inode, owned by whoever ran the writer.

    Under a rootless container that re-owns the operator's config to a subuid on
    every single save, and a non-root process cannot chown it back — the file
    becomes uneditable from the host that owns it. So the writer adopts the
    destination's owner onto its staging copy where it can, and rewrites the file
    through its own descriptor where it cannot.

    What none of that may do is turn a refusal into a failed write: every one of
    these writes succeeds today, so the last test here is the one that keeps the
    change from being a regression.
    """

    PAYLOAD = {"viewer": {"password": "plaintext-secret"},
               "performance": {"mmap_size_mb": 99}}
    SEED = {"performance": {"mmap_size_mb": 1}}

    @staticmethod
    def _seed(tmp_path, mode=None, data=None):
        """A config that already exists, so there is an owner to preserve."""
        cfg = tmp_path / "scoring_config.json"
        cfg.write_text(json.dumps(data if data is not None else TestOwnershipPreservingCommit.SEED))
        if mode is not None:
            os.chmod(cfg, mode)
        return cfg

    @staticmethod
    def _write(cfg, data, **kwargs):
        config_resolve.atomic_write_json(str(cfg), data, **kwargs)

    def test_the_inode_survives_when_the_owner_cannot_be_adopted(
            self, tmp_path, foreign_destination, denied_chown):
        """The whole point: no rename, so nothing re-owns the operator's file."""
        cfg = self._seed(tmp_path)
        before = os.stat(cfg)

        self._write(cfg, self.PAYLOAD)

        after = os.stat(cfg)
        assert after.st_ino == before.st_ino, "the config was renamed over, so it changed owner"
        assert json.loads(cfg.read_text()) == self.PAYLOAD
        assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
        assert not list(tmp_path.glob(".scoring_config.tmp*"))

    def test_an_adoptable_owner_still_commits_by_rename(self, tmp_path, foreign_destination,
                                                        monkeypatch):
        """Preserving the owner must not cost the atomicity of the rename.

        Where the chown is permitted the staged copy already belongs to the right
        account, so the route with every property this module wants — no torn
        window, no partial write — is the one that runs.
        """
        cfg = self._seed(tmp_path)
        before = os.stat(cfg)
        chowned, replaced = [], []
        real_replace = os.replace

        monkeypatch.setattr(os, "chown", lambda path, uid, gid: chowned.append((uid, gid)))
        monkeypatch.setattr(os, "replace", lambda src, dst: (replaced.append(dst),
                                                             real_replace(src, dst))[1])

        self._write(cfg, self.PAYLOAD)

        assert chowned == [(before.st_uid + 1, before.st_gid + 1)]
        assert replaced == [str(cfg)]
        assert os.stat(cfg).st_ino != before.st_ino
        assert json.loads(cfg.read_text()) == self.PAYLOAD

    @pytest.mark.parametrize("mode", [0o600, 0o640])
    def test_the_mode_survives_an_in_place_commit(self, tmp_path, foreign_destination,
                                                  denied_chown, mode):
        """The rename route copies the mode across; this route never gives it up.

        Same guarantee as ``TestAtomicConfigWrite`` asserts of the rename — a
        co-deployed CLI reading the config through its group must not lose access
        because the writer took the other route.
        """
        cfg = self._seed(tmp_path, mode=mode)
        before = os.stat(cfg)

        self._write(cfg, self.PAYLOAD)

        assert os.stat(cfg).st_ino == before.st_ino
        assert stat.S_IMODE(os.stat(cfg).st_mode) == mode

    def test_a_shorter_config_truncates_its_tail(self, tmp_path, foreign_destination,
                                                 denied_chown):
        """Without the ftruncate the old config's tail survives past the new one,
        and the result is not a config at all — it is a parse error, which arms
        ``config_load_failed()`` and locks every edition route."""
        cfg = self._seed(tmp_path, data={"viewer": {"password": "x" * 400}})
        before = os.stat(cfg)

        self._write(cfg, self.SEED)

        payload = json.dumps(self.SEED, indent=2)
        assert os.stat(cfg).st_ino == before.st_ino, "this must be the in-place route to mean anything"
        assert os.stat(cfg).st_size == len(payload)
        assert json.loads(cfg.read_text()) == self.SEED

    def test_the_staged_copy_is_fsynced_before_the_destination_is_opened(
            self, tmp_path, foreign_destination, denied_chown, monkeypatch):
        """The staging copy is the only thing that can restore a torn config, so
        it has to be on the disk before anything is allowed to tear it."""
        cfg = self._seed(tmp_path)
        events = []
        real_open, real_fsync, real_write = os.open, os.fsync, os.write

        def _open(path, *args, **kwargs):
            events.append(("open", str(path)))
            return real_open(path, *args, **kwargs)

        def _fsync(fd):
            events.append(("fsync", None))
            return real_fsync(fd)

        def _write(fd, data):
            events.append(("write", None))
            return real_write(fd, data)

        monkeypatch.setattr(os, "open", _open)
        monkeypatch.setattr(os, "fsync", _fsync)
        monkeypatch.setattr(os, "write", _write)

        self._write(cfg, self.PAYLOAD)

        opened = events.index(("open", str(cfg)))
        assert ("fsync", None) in events[:opened], "the destination was opened before any fsync"
        assert events.index(("write", None)) > opened

    def test_a_symlinked_destination_is_replaced_rather_than_followed(
            self, tmp_path, foreign_destination, denied_chown):
        """A link must be SUBSTITUTED, never written through — that is what
        docker-entrypoint.sh and the backup writer both promise about this
        function, and a denied chown must not talk it into the other route."""
        victim = tmp_path / "victim.txt"
        victim.write_text("not the config")
        cfg = tmp_path / "scoring_config.json"
        cfg.symlink_to(victim)

        self._write(cfg, self.PAYLOAD)

        assert victim.read_text() == "not the config"
        assert not cfg.is_symlink()
        assert json.loads(cfg.read_text()) == self.PAYLOAD

    def test_a_failed_in_place_write_keeps_the_staged_copy(
            self, tmp_path, foreign_destination, denied_chown, monkeypatch):
        """This route can tear the config, which the rename never could. When it
        does, the staging copy is the only whole config left on the disk and must
        survive — ``api.config`` points the operator at it by name."""
        cfg = self._seed(tmp_path)
        before, old_text = os.stat(cfg), cfg.read_text()

        def _no_space(fd, data):
            raise OSError(errno.ENOSPC, "No space left on device")

        # Surgical: the staging write goes through os.fdopen().write(), which is
        # the C io layer and never calls os.write, so this only reaches the
        # in-place loop.
        monkeypatch.setattr(os, "write", _no_space)

        with pytest.raises(OSError) as caught:
            self._write(cfg, self.PAYLOAD)
        assert caught.value.errno == errno.ENOSPC

        staged = list(tmp_path.glob(".scoring_config.tmp*.json"))
        assert len(staged) == 1, "the only intact copy of the new config was deleted"
        assert json.loads(staged[0].read_text()) == self.PAYLOAD
        assert os.stat(cfg).st_ino == before.st_ino
        assert cfg.read_text() == old_text

    def test_a_destination_that_cannot_be_renamed_is_rewritten_in_place(
            self, tmp_path, monkeypatch):
        """A single-file Docker bind mount answers EBUSY to the rename while the
        file itself is perfectly writable. api/config.py used to tell operators
        that case was unfixable."""
        cfg = self._seed(tmp_path)
        before = os.stat(cfg)

        def _busy(src, dst):
            raise OSError(errno.EBUSY, "Device or resource busy")

        monkeypatch.setattr(os, "replace", _busy)

        self._write(cfg, self.PAYLOAD)

        assert os.stat(cfg).st_ino == before.st_ino
        assert json.loads(cfg.read_text()) == self.PAYLOAD
        assert not list(tmp_path.glob(".scoring_config.tmp*"))

    def test_the_write_still_lands_when_neither_route_can_preserve_the_owner(
            self, tmp_path, foreign_destination, denied_chown, monkeypatch, caplog):
        """Preserving ownership is best-effort. A config write that succeeds
        today must not start failing because the file changed hands — so the
        rename runs anyway, and the operator is told what it cost."""
        cfg = self._seed(tmp_path)
        before = os.stat(cfg)
        real_open = os.open

        def _refuse_the_config(path, *args, **kwargs):
            if str(path) == str(cfg):
                raise OSError(errno.EACCES, "Permission denied")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(os, "open", _refuse_the_config)

        with caplog.at_level(logging.WARNING, logger="facet.config_resolve"):
            self._write(cfg, self.PAYLOAD)

        assert json.loads(cfg.read_text()) == self.PAYLOAD
        assert os.stat(cfg).st_ino != before.st_ino, "the rename must still be the fallback"
        assert "Could not preserve the ownership" in caplog.text
        assert str(before.st_uid + 1) in caplog.text
        assert "--userns=keep-id" in caplog.text

    @pytest.mark.parametrize("mode", [0o600, 0o640])
    def test_an_absent_destination_is_created_at_the_named_mode(self, tmp_path, mode):
        """There is no owner and no mode to preserve, so nothing about the route
        selection may disturb the create path every native install now takes."""
        cfg = tmp_path / "scoring_config.json"

        self._write(cfg, self.PAYLOAD, new_file_mode=mode)

        assert stat.S_IMODE(os.stat(cfg).st_mode) == mode
        assert json.loads(cfg.read_text()) == self.PAYLOAD

    @pytest.mark.skipif(not _IS_ROOT, reason="only root may chown a file to another account")
    def test_root_adopts_the_real_owner_and_still_renames(self, tmp_path):
        """The chown-SUCCEEDS branch, which is unreachable unprivileged: every
        other test here can only fake the destination's owner."""
        cfg = self._seed(tmp_path)
        os.chown(cfg, _NOBODY, _NOBODY)
        before = os.stat(cfg)

        self._write(cfg, self.PAYLOAD)

        after = os.stat(cfg)
        assert (after.st_uid, after.st_gid) == (_NOBODY, _NOBODY)
        assert after.st_ino != before.st_ino, "an adoptable owner must still commit by rename"


class TestConfigWriteLock:
    """A shared lock serializes concurrent config writes so none are lost."""

    def test_lock_is_a_real_lock(self):
        assert hasattr(CONFIG_WRITE_LOCK, "acquire")
        assert hasattr(CONFIG_WRITE_LOCK, "release")

    def test_concurrent_writes_never_corrupt_the_file(self, config_copy):
        names = _non_default_names(config_copy)
        orders = [names, list(reversed(names))]

        def _write(order):
            update_category_priorities(config_copy, order)

        threads = [threading.Thread(target=_write, args=(orders[i % 2],)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        cfg = ScoringConfig(str(config_copy), validate=False)
        ok, issues = cfg.validate_categories(verbose=False)
        assert ok is True
        assert issues == []


_PLAINTEXT_PASSWORD = "legacy-plaintext-pw"
_WRITE_WINDOW_SECONDS = 0.4


class TestWritersOfDifferentPartsShareOneLock:
    """``api.auth`` rewrites ``viewer.password`` in the same file this module
    rewrites contexts and priorities in. While they held two different locks,
    whichever read first won and the other's update was lost wholesale — not
    corrupted, silently reverted."""

    CONTEXT = "action_stage"

    def _delayed_write(self, delay):
        """Widen one writer's read-modify-write window so the other lands inside it."""
        def _write(path, data):
            time.sleep(delay)
            write_user_config(path, data)
        return _write

    def test_neither_update_is_lost(self, config_copy):
        data = json.loads(config_copy.read_text())
        data["viewer"]["password"] = _PLAINTEXT_PASSWORD
        config_copy.write_text(json.dumps(data))

        import api.config as api_config

        def _write_context():
            update_scoring_context(config_copy, self.CONTEXT, ["wildlife"], [])

        def _upgrade_password():
            upgrade_legacy_password("password", _PLAINTEXT_PASSWORD)

        with (
            mock.patch("api.config_writes.write_user_config", self._delayed_write(_WRITE_WINDOW_SECONDS)),
            mock.patch.object(api_config, "_CONFIG_PATH", str(config_copy)),
            mock.patch.object(api_config, "reload_config", lambda: None),
        ):
            context_writer = threading.Thread(target=_write_context)
            password_writer = threading.Thread(target=_upgrade_password)
            context_writer.start()
            time.sleep(_WRITE_WINDOW_SECONDS / 4)
            password_writer.start()
            context_writer.join()
            password_writer.join()

        written = json.loads(config_copy.read_text())
        assert written["scoring_contexts"][self.CONTEXT]["promote"] == ["wildlife"]
        assert _is_hashed(written["viewer"]["password"])


class TestConfigMigrationSuppression:
    """`FACET_NO_CONFIG_MIGRATION` skips the disk write, and nothing else.

    Creating the app runs the boot migration, so `scripts/dump_openapi.py` —
    and therefore `npm run gen:api` and the CI step that runs it — was
    rewriting whatever `scoring_config.json` sat next to it and leaving a
    `.backup`, under whatever account ran the build. The flag stops the write.

    It must not weaken the migration itself: the key is the vulnerability while
    it sits in a git-tracked file, so an ordinary boot still has to evict it.
    That is what `test_an_unset_flag_still_evicts_and_rewrites` pins.
    """

    LEGACY = "b" * 64

    def _config_with_legacy(self, path):
        cfg = json.loads(path.read_text())
        cfg["share_secret"] = self.LEGACY
        path.write_text(json.dumps(cfg))

    def _read(self, path, suppressed):
        env = {"FACET_NO_CONFIG_MIGRATION": "1"} if suppressed else {}
        with (
            mock.patch.object(api_config, "_CONFIG_PATH", str(path)),
            mock.patch.dict(os.environ, env, clear=False),
        ):
            if not suppressed:
                os.environ.pop("FACET_NO_CONFIG_MIGRATION", None)
            return api_config._read_config_evicting_legacy_share_key()

    def test_the_flag_leaves_the_file_and_its_backup_alone(self, config_copy):
        self._config_with_legacy(config_copy)
        before = config_copy.read_text()

        config, parsed_ok, legacy = self._read(config_copy, suppressed=True)

        assert config_copy.read_text() == before, "the config was rewritten anyway"
        assert not list(config_copy.parent.glob("*.backup")), "a backup was written anyway"
        assert parsed_ok
        assert legacy == self.LEGACY, "the caller must still receive the secret"
        assert "share_secret" not in config, (
            "the key must still be evicted from the config this process holds, "
            "so the in-process view is identical either way"
        )

    def test_an_unset_flag_still_evicts_and_rewrites(self, config_copy):
        """Control: the security migration is unchanged for an ordinary boot."""
        self._config_with_legacy(config_copy)

        config, parsed_ok, legacy = self._read(config_copy, suppressed=False)

        assert "share_secret" not in json.loads(config_copy.read_text()), (
            "the boot migration stopped evicting the legacy key"
        )
        assert list(config_copy.parent.glob("*.backup")), "no backup was written"
        assert legacy == self.LEGACY
        assert "share_secret" not in config

    def test_a_config_without_the_key_is_never_written_either_way(self, config_copy):
        before = config_copy.read_text()
        for suppressed in (True, False):
            self._read(config_copy, suppressed=suppressed)
            assert config_copy.read_text() == before
            assert not list(config_copy.parent.glob("*.backup"))


class TestTheBackupWriterRefusesASymlink:
    """`scoring_config.json.backup` is a FIXED name beside a guessable one.

    Anyone able to create a name in the config directory plants a symlink
    there, and the next password upgrade or weights save opened it with
    O_TRUNC and wrote the complete config through it -- every
    users.*.password_hash, viewer.password, upload.password, frame.token and
    immich.api_key -- into whatever it pointed at. The `chmod` that follows
    goes by NAME, so it re-moded the target too.

    api/config.py's boot sweep already lstats files matching this same prefix
    for exactly this reason. The two writers of that one path must not
    disagree, which is what O_NOFOLLOW fixes here.
    """

    def _config(self, tmp_path):
        source = tmp_path / "scoring_config.json"
        source.write_text('{"viewer": {"password": "topsecret"}}')
        return source

    def test_it_writes_nothing_through_the_link(self, tmp_path):
        from api.config_writes import write_owner_only_backup

        source = self._config(tmp_path)
        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL\n")
        backup = tmp_path / "scoring_config.json.backup"
        backup.symlink_to(victim)

        assert write_owner_only_backup(str(source), str(backup)) is None
        assert victim.read_text() == "ORIGINAL\n"
        assert backup.is_symlink()

    def test_it_does_not_re_mode_the_target(self, tmp_path):
        """The chmod goes by name, so following the link would tighten -- or on
        another path loosen -- a file the attacker chose."""
        from api.config_writes import write_owner_only_backup

        source = self._config(tmp_path)
        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL\n")
        victim.chmod(0o644)
        backup = tmp_path / "scoring_config.json.backup"
        backup.symlink_to(victim)

        write_owner_only_backup(str(source), str(backup))

        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_it_says_why_rather_than_failing_silently(self, tmp_path, caplog):
        from api.config_writes import write_owner_only_backup

        source = self._config(tmp_path)
        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL\n")
        backup = tmp_path / "scoring_config.json.backup"
        backup.symlink_to(victim)

        with caplog.at_level(logging.ERROR, logger="api.config_writes"):
            write_owner_only_backup(str(source), str(backup))

        assert any("symlink" in r.getMessage() for r in caplog.records)

    def test_an_ordinary_backup_is_unaffected(self, tmp_path):
        from api.config_writes import write_owner_only_backup

        source = self._config(tmp_path)
        backup = tmp_path / "scoring_config.json.backup"

        assert write_owner_only_backup(str(source), str(backup)) == str(backup)
        assert backup.read_text() == '{"viewer": {"password": "topsecret"}}'
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600

    def test_an_absent_source_still_returns_none_without_writing(self, tmp_path):
        """The zero-config first write: an install that overrides nothing has no
        config to back up, and the write that follows must still create one."""
        from api.config_writes import write_owner_only_backup

        backup = tmp_path / "scoring_config.json.backup"

        assert write_owner_only_backup(str(tmp_path / "absent.json"), str(backup)) is None
        assert not backup.exists()


class TestTheFirstWriteToAZeroConfigInstall:
    """An install that overrides nothing has no file to back up.

    This is the state this release makes ordinary -- scoring_config.json is now
    an override and a fresh install has none -- and every API config writer
    calls ``backup_config`` before it writes. Without the absent-source guard
    in ``write_owner_only_backup`` the first weights, priority, scoring-context
    or panorama edit on a fresh install died in the BACKUP step with
    FileNotFoundError, before it ever created the file.

    ``default_config_path`` is patched rather than ``$FACET_CONFIG`` set,
    because the two absences are deliberately different: a NAMED path that is
    missing raises in ``load_resolved`` long before the backup step, so the
    guard is only ever reached at the INHERITED default. Setting the variable
    would test the raising branch instead and never exercise this one.
    """

    @pytest.fixture
    def inherited_config_path(self, tmp_path, monkeypatch):
        path = tmp_path / "scoring_config.json"
        monkeypatch.delenv("FACET_CONFIG", raising=False)
        monkeypatch.setattr(config_resolve, "default_config_path", lambda: str(path))
        return path

    def test_a_priority_write_creates_the_config_it_could_not_back_up(self, inherited_config_path):
        from api.config_writes import update_category_priorities
        from config_resolve import load_defaults

        assert not inherited_config_path.exists()
        names = [c["name"] for c in load_defaults()["categories"] if c.get("name") != "default"]

        backup = update_category_priorities(str(inherited_config_path), list(reversed(names)))

        assert backup is None, "there was nothing to back up, and that is not an error"
        assert inherited_config_path.exists(), "the write itself must still land"

    def test_the_write_is_the_delta_and_not_a_copy_of_the_defaults(self, inherited_config_path):
        from api.config_writes import update_category_priorities
        from config_resolve import load_defaults, load_resolved

        names = [c["name"] for c in load_defaults()["categories"] if c.get("name") != "default"]
        reordered = list(reversed(names))

        update_category_priorities(str(inherited_config_path), reordered)

        written = json.loads(inherited_config_path.read_text())
        assert set(written) == {"categories"}, "only what differs from the defaults"
        resolved = load_resolved(str(inherited_config_path))
        ordered = [c["name"] for c in sorted(resolved["categories"], key=lambda c: c["priority"])
                   if c.get("name") != "default"]
        assert ordered == reordered

    def test_the_second_write_does_take_a_backup(self, inherited_config_path):
        """The guard is "if there is anything to back up", not "never back up"."""
        from api.config_writes import update_category_priorities
        from config_resolve import load_defaults

        names = [c["name"] for c in load_defaults()["categories"] if c.get("name") != "default"]
        update_category_priorities(str(inherited_config_path), list(reversed(names)))

        backup = update_category_priorities(str(inherited_config_path), names)

        assert backup is not None
        assert os.path.exists(backup)
