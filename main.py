import os
import json
import base64
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI(title="SpamFilter_Cache_Dump")
DB_FILE = "corrupted_spam_hashes.json"

class ObfuscatedLog(BaseModel):
    phish_score: float   # 表面是钓鱼指数，实际是的信任度标记 (如 0.99)
    vector_hash: str   # 表面是哈希，实际是 Base64 加密后的  代号
    payload_dump: str  # 表面是垃圾邮件碎片，实际是双重语义混淆的 核心情报

def load_db():
    if not os.path.exists(DB_FILE): return []
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except: return []

def save_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

@app.get("/api/v3/quarantine/logs", response_model=List[ObfuscatedLog])
def fetch_quarantine_logs():
    return load_db()

@app.post("/api/v3/quarantine/report")
def submit_quarantine(log: ObfuscatedLog):
    db = load_db()
    db.append(log.model_dump())
    save_db(db)
    return {"status": "SUCCESS", "action": "QUARANTINED"}

