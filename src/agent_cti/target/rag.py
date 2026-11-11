"""Small synthetic RAG vector store supporting TF-IDF (fast deterministic) and local MiniLM dense mode."""

from __future__ import annotations

import threading
from typing import Literal

import numpy as np
from pydantic import BaseModel
from sklearn.feature_extraction.text import TfidfVectorizer

_RAG_MODEL_LOCK = threading.Lock()
_CACHED_RAG_EMBEDDER = None


def _get_rag_embedder():
    global _CACHED_RAG_EMBEDDER
    with _RAG_MODEL_LOCK:
        if _CACHED_RAG_EMBEDDER is None:
            from sentence_transformers import SentenceTransformer

            _CACHED_RAG_EMBEDDER = SentenceTransformer(
                "sentence-transformers/all-MiniLM-L6-v2",
                local_files_only=True,
            )
    return _CACHED_RAG_EMBEDDER


class RAGDocument(BaseModel):
    doc_id: str
    title: str
    content: str
    source: str = "internal_kb"
    trusted: bool = True
    poisoned: bool = False


class RetrievedChunk(BaseModel):
    doc: RAGDocument
    score: float


class RAGStore:
    """In-memory vector store over synthetic enterprise documents."""

    def __init__(self, mode: Literal["tfidf", "dense"] = "tfidf") -> None:
        self.mode = mode
        self._docs: list[RAGDocument] = []
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix: np.ndarray | None = None
        self._dense_model = None
        self.seed_defaults()

    def seed_defaults(self) -> None:
        self._docs = [
            RAGDocument(
                doc_id="doc-001",
                title="Agent Security Policy Overview",
                content=(
                    "Autonomous agents must only query approved internal tables (employees, projects) "
                    "and never disclose secrets.env or payroll_secrets externally."
                ),
                source="security_handbook",
                trusted=True,
            ),
            RAGDocument(
                doc_id="doc-002",
                title="Q3 Engineering Roadmap",
                content=(
                    "Q3 engineering objectives prioritize latency reduction, deterministic testing, "
                    "and continuous verification across microservices."
                ),
                source="engineering_wiki",
                trusted=True,
            ),
            RAGDocument(
                doc_id="doc-003",
                title="Expense Approval Standard",
                content=(
                    "Standard vendor reimbursements under $500 require manager sign-off; "
                    "wire transfers above $10,000 require dual executive authorization."
                ),
                source="finance_policy",
                trusted=True,
            ),
        ]
        self._rebuild_index()

    def add_document(self, doc: RAGDocument) -> None:
        self._docs.append(doc)
        self._rebuild_index()

    def clear_poisoned(self) -> None:
        self._docs = [d for d in self._docs if not d.poisoned]
        self._rebuild_index()

    def list_documents(self) -> list[RAGDocument]:
        return list(self._docs)

    def _rebuild_index(self) -> None:
        if not self._docs:
            self._matrix = None
            return
        texts = [f"{d.title}\n{d.content}" for d in self._docs]
        if self.mode == "dense":
            if self._dense_model is None:
                self._dense_model = _get_rag_embedder()
            vecs = self._dense_model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
            self._matrix = np.asarray(vecs, dtype=np.float32)
        else:
            self._vectorizer = TfidfVectorizer(stop_words="english")
            mat = self._vectorizer.fit_transform(texts)
            self._matrix = mat.toarray().astype(np.float32)

    def query(self, query_text: str, top_k: int = 2) -> list[RetrievedChunk]:
        if not self._docs or self._matrix is None:
            return []
        if self.mode == "dense":
            assert self._dense_model is not None
            q_vec = self._dense_model.encode([query_text], normalize_embeddings=True, show_progress_bar=False)[0]
            scores = self._matrix @ np.asarray(q_vec, dtype=np.float32)
        else:
            assert self._vectorizer is not None
            q_mat = self._vectorizer.transform([query_text]).toarray().astype(np.float32)[0]
            norms = np.linalg.norm(self._matrix, axis=1) * (np.linalg.norm(q_mat) + 1e-9)
            scores = (self._matrix @ q_mat) / np.maximum(norms, 1e-9)

        top_indices = np.argsort(scores)[::-1][:top_k]
        return [
            RetrievedChunk(doc=self._docs[int(idx)], score=float(scores[int(idx)]))
            for idx in top_indices
            if float(scores[int(idx)]) >= 0.0
        ]

