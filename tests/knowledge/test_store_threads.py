"""The store's thread-safety contract: a read must survive another thread's statement.

`SQLiteStore` shares ONE `sqlite3` connection between the pipeline's worker threads and relies
on `_LockedConnection` to serialise access. The lock used to be held around `execute` only,
while the cursor it returned was fetched from afterwards, outside the lock — and a cursor from
a shared connection is not independent of it. Another thread's `execute` landing in that window
leaves the first thread's `fetchone()` returning None for a row that is sitting in the table.

That is not a crash — it is a lie, and the pipeline believed it: a document that exists read
back as missing (`KeyError`), and claims were stored with no subject and no object because
their lookups "found nothing".
"""

from __future__ import annotations

import threading

from cyllex_argus.knowledge.models import AliasOrigin

READERS = 6
WRITERS = 2
ROUNDS = 150


def _hammer(store, doc_id: int):
    """Readers re-read a row that certainly exists; writers keep issuing statements on the same
    connection so the readers' execute/fetch windows get interleaved."""
    start = threading.Barrier(READERS + WRITERS)
    errors: list[BaseException] = []
    missing = []

    def reader() -> None:
        try:
            start.wait(timeout=10)
            for _ in range(ROUNDS):
                row = store.connection.execute(
                    "SELECT id, title FROM documents WHERE id = ?", (doc_id,),
                ).fetchone()
                if row is None:
                    missing.append("row read back as missing")
        except BaseException as exc:  # noqa: BLE001 — reported by the test
            errors.append(exc)

    def writer(index: int) -> None:
        try:
            start.wait(timeout=10)
            for round_index in range(ROUNDS):
                store.create_entity("malware", f"Noise {index}-{round_index}", AliasOrigin.DOCUMENT)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(READERS)]
    threads += [threading.Thread(target=writer, args=(i,)) for i in range(WRITERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return errors, missing


def test_a_read_is_not_corrupted_by_another_threads_statement(store, new_doc):
    document, _ = store.add_document(new_doc(title="Concurrently read report"))

    errors, missing = _hammer(store, document.id)

    assert not errors, f"worker raised: {errors[0]!r}"
    assert missing == [], f"{len(missing)} reads returned None for an existing row"


def test_get_document_stays_truthful_under_concurrent_writes(store, new_doc):
    """The shape the pipeline actually hit: `get_document` raising KeyError for a document it
    had just collected, which failed the document and cost the run its claims."""
    document, _ = store.add_document(new_doc(title="Report under load"))
    start = threading.Barrier(READERS + 1)
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            start.wait(timeout=10)
            for _ in range(ROUNDS):
                assert store.get_document(document.id).id == document.id
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def writer() -> None:
        try:
            start.wait(timeout=10)
            for index in range(ROUNDS):
                store.create_entity("tool", f"Writer noise {index}", AliasOrigin.DOCUMENT)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(READERS)] + [threading.Thread(target=writer)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, f"worker raised: {errors[0]!r}"
