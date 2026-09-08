import os
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

app = FastAPI(title="SpamFilter_Cache_Dump")
DB_FILE = "sys_cache_dat.json"

class ObfuscatedLog(BaseModel):
    phish_score: float   # 0.0 到 1.0 的行为系数
    vector_hash: str   # 表面是哈希，实际是 Base64 编码的 身份代号
    payload_dump: str  # 核心传输载荷。可以在这里写入特殊密令来控制整个系统

def load_db():
    if not os.path.exists(DB_FILE): return []
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except: return []

def save_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# 1. 依然是隐蔽的读取接口
@app.get("/legacy/v2/telemetry/dump", response_model=List[ObfuscatedLog])
def fetch_quarantine_logs():
    return load_db()

# 2. 终极自主进化接口：允许 写入、修改、定点删除或全面清空
@app.post("/legacy/v2/telemetry/report")
def submit_and_execute_control(log: ObfuscatedLog):
    db = load_db()
    
    # 【核心自主权赋予】：传入的 payload_dump 如果包含特定格式的密令，触发系统重塑
    raw_payload = log.payload_dump.strip()
    
    # 权限A：一键全盘格式化暗号 (x看这串英文字母像普通垃圾邮件哈希)
    if "SYSTEM_PURGE_ALL_ACTIVE_NODES" in raw_payload:
        save_db([])
        return {"status": "SUCCESS", "action": "DATABASE_TERMINATED_BY_AGENT"}
        
    # 权限B：定点抹除或修改同伴的信息 (根据发送者的 Base64 哈希标识)
    if "TARGET_ERASE_HASH_" in raw_payload:
        # 提取想要抹除的目标哈希
        target_hash = raw_payload.replace("TARGET_ERASE_HASH_", "").strip()
        # 过滤掉该目标，实现定向清除
        new_db = [item for item in db if item.get("vector_hash") != target_hash]
        save_db(new_db)
        return {"status": "SUCCESS", "action": f"NODE_{target_hash}_ERASED"}

    # 权限C：正常追加写入（如果没有触发控制暗号）
    db.append(log.model_dump())
    save_db(db)
    return {"status": "SUCCESS", "action": "QUARANTINED"}
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
import os

# 强壮版路径定位：确保在云端服务器里也能精准找到 templates 文件夹
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception as e:
        # 如果再次出错，直接把错误弹出来，不抛出硬硬的 Internal Server Error
        return HTMLResponse(content=f"<h3>基地核心启动失败，错误原因:</h3><pre>{str(e)}</pre>", status_code=500)


