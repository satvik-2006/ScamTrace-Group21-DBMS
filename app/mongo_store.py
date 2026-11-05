"""MongoDB document store for unstructured report evidence and full-text retrieval.

SQL remains the source of truth for users, reports, moderation and indicators.
MongoDB stores searchable evidence documents linked by SQL report_id.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
try:
    from pymongo import MongoClient, TEXT
    from pymongo.errors import PyMongoError
except ImportError:  # SQL-only dev/test environments can still run; Mongo is enabled by requirements install.
    MongoClient = None
    TEXT = None
    class PyMongoError(Exception):
        pass

_client = None
_db = None

def get_collection():
    global _client, _db
    uri = os.getenv('MONGODB_URI', '').strip()
    if not uri or MongoClient is None:
        return None
    if _db is None:
        _client = MongoClient(uri, serverSelectionTimeoutMS=1800, connectTimeoutMS=1800)
        _db = _client[os.getenv('MONGODB_DATABASE', 'scamtrace_evidence')]
        _db.evidence.create_index([('content', TEXT), ('tags', TEXT)], name='evidence_text_search')
        _db.evidence.create_index([('report_id', 1), ('created_at', -1)], name='evidence_report_lookup')
    return _db.evidence

def store_evidence(report_id: int, evidence_type: str, content: str, metadata: dict | None = None):
    collection = get_collection()
    if collection is None or not content.strip():
        return None
    doc = {'report_id': int(report_id), 'evidence_type': evidence_type,
           'content': content.strip(), 'metadata': metadata or {},
           'tags': [evidence_type.lower(), 'scamtrace'],
           'created_at': datetime.now(timezone.utc)}
    result = collection.insert_one(doc)
    return str(result.inserted_id)

def search_evidence(query: str, limit: int = 10):
    if len(query.strip()) < 3:
        return []
    try:
        collection = get_collection()
        if collection is None:
            return []
        rows = collection.find({'$text': {'$search': query}},
            {'score': {'$meta': 'textScore'}, 'content': 1, 'report_id': 1,
             'evidence_type': 1, 'created_at': 1}).sort([('score', {'$meta': 'textScore'})]).limit(limit)
        return [{'report_id': r['report_id'], 'evidence_type': r.get('evidence_type'),
                 'content': r.get('content', '')[:500], 'score': round(r.get('score', 0), 3),
                 'created_at': r.get('created_at').isoformat() if r.get('created_at') else None}
                for r in rows]
    except PyMongoError:
        return []

def status():
    if not os.getenv('MONGODB_URI', '').strip():
        return {'configured': False, 'connected': False, 'message': 'Set MONGODB_URI to enable document search'}
    if MongoClient is None:
        return {'configured': True, 'connected': False, 'message': 'Install requirements.txt to enable MongoDB support'}
    try:
        get_collection().database.command('ping')
        return {'configured': True, 'connected': True, 'message': 'MongoDB document store online'}
    except PyMongoError as exc:
        return {'configured': True, 'connected': False, 'message': f'MongoDB unavailable: {type(exc).__name__}'}
