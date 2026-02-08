#!/usr/bin/env python3
# key_automaton.py - API Key Management Service
# AI-powered intelligent credential management with autonomous allocation and rotation

import os
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import json

# Initialize FastAPI
app = FastAPI(
    title="API Key Automaton",
    description="AI-powered intelligent credential management with autonomous allocation and rotation",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
admin_api_key_header = APIKeyHeader(name="x-admin-api-key", auto_error=False)
ADMIN_KEYS = {os.getenv("ADMIN_API_KEY", "demo-admin-key-change-me")}

def require_admin(api_key: str = Depends(admin_api_key_header)):
    if api_key not in ADMIN_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin API key"
        )
    return api_key

# Models
class KeyCreate(BaseModel):
    system_name: str
    system_type: str
    env: str
    name: str
    key_ref: str

class AllocationCreate(BaseModel):
    key_id: str
    consumer_type: str
    consumer_id: str
    scope: dict

class KeyOut(BaseModel):
    id: str
    name: str
    system_name: str
    system_type: str
    env: str
    status: str
    last_used_at: Optional[datetime]
    last_rotated_at: Optional[datetime]
    allocated_to: List[str]

# In-memory storage (replace with real DB)
api_keys_db = [
    {
        "id": "key-001",
        "name": "Production Database",
        "system_name": "PostgreSQL",
        "system_type": "db",
        "env": "prod",
        "status": "active",
        "last_used_at": datetime(2024, 2, 7, 12, 0, 0),
        "last_rotated_at": datetime(2024, 2, 1, 0, 0, 0),
        "allocated_to": ["Server-01", "Server-02"]
    },
    {
        "id": "key-002",
        "name": "Payment Gateway",
        "system_name": "Stripe",
        "system_type": "payments",
        "env": "prod",
        "status": "active",
        "last_used_at": datetime(2024, 2, 6, 18, 30, 0),
        "last_rotated_at": datetime(2024, 1, 15, 0, 0, 0),
        "allocated_to": ["API-Gateway"]
    },
    {
        "id": "key-003",
        "name": "Cloud Storage",
        "system_name": "AWS S3",
        "system_type": "storage",
        "env": "prod",
        "status": "active",
        "last_used_at": None,
        "last_rotated_at": datetime(2024, 2, 5, 0, 0, 0),
        "allocated_to": []
    }
]

allocations_db = []
audit_log_db = []

# Routes
@app.get("/")
def root():
    return {
        "service": "API Key Automaton",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "keys_count": len(api_keys_db)
    }

@app.post("/keys", dependencies=[Depends(require_admin)])
def create_key(payload: KeyCreate):
    key_id = f"key-{len(api_keys_db) + 1:03d}"
    new_key = {
        "id": key_id,
        "name": payload.name,
        "system_name": payload.system_name,
        "system_type": payload.system_type,
        "env": payload.env,
        "status": "active",
        "last_used_at": None,
        "last_rotated_at": datetime.now(),
        "allocated_to": []
    }
    api_keys_db.append(new_key)
    
    audit_log_db.append({
        "timestamp": datetime.now().isoformat(),
        "action": "create_key",
        "key_id": key_id,
        "details": f"Created key '{payload.name}'"
    })
    
    return {"status": "ok", "key_id": key_id}

@app.get("/keys", response_model=List[KeyOut], dependencies=[Depends(require_admin)])
def list_keys():
    return api_keys_db

@app.get("/keys/{key_id}", response_model=KeyOut, dependencies=[Depends(require_admin)])
def get_key(key_id: str):
    for key in api_keys_db:
        if key["id"] == key_id:
            return key
    raise HTTPException(status_code=404, detail="Key not found")

@app.post("/allocations", dependencies=[Depends(require_admin)])
def allocate_key(payload: AllocationCreate):
    # Find the key
    key_found = None
    for key in api_keys_db:
        if key["id"] == payload.key_id:
            key_found = key
            break
    
    if not key_found:
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Add allocation
    if payload.consumer_id not in key_found["allocated_to"]:
        key_found["allocated_to"].append(payload.consumer_id)
    
    allocation = {
        "id": f"alloc-{len(allocations_db) + 1:03d}",
        "key_id": payload.key_id,
        "consumer_type": payload.consumer_type,
        "consumer_id": payload.consumer_id,
        "scope": payload.scope,
        "created_at": datetime.now().isoformat()
    }
    allocations_db.append(allocation)
    
    audit_log_db.append({
        "timestamp": datetime.now().isoformat(),
        "action": "allocate_key",
        "key_id": payload.key_id,
        "details": f"Allocated to {payload.consumer_id}"
    })
    
    return {"status": "allocated", "allocation_id": allocation["id"]}

@app.get("/allocations", dependencies=[Depends(require_admin)])
def list_allocations():
    return allocations_db

@app.post("/keys/{key_id}/rotate", dependencies=[Depends(require_admin)])
def rotate_key(key_id: str):
    key_found = None
    for key in api_keys_db:
        if key["id"] == key_id:
            key_found = key
            break
    
    if not key_found:
        raise HTTPException(status_code=404, detail="Key not found")
    
    key_found["last_rotated_at"] = datetime.now()
    
    audit_log_db.append({
        "timestamp": datetime.now().isoformat(),
        "action": "rotate_key",
        "key_id": key_id,
        "details": f"Rotated key '{key_found['name']}'"
    })
    
    return {"status": "rotated", "key_id": key_id}

@app.get("/audit-log", dependencies=[Depends(require_admin)])
def get_audit_log():
    return audit_log_db[-100:]  # Last 100 entries

@app.post("/system-requests", dependencies=[Depends(require_admin)])
def system_request(payload: dict):
    audit_log_db.append({
        "timestamp": datetime.now().isoformat(),
        "action": "system_request",
        "details": json.dumps(payload)
    })
    return {"status": "logged"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
