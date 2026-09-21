from __future__ import annotations
import hashlib, json, time

class Ledger:
    def __init__(self):
        self.blocks=[]
        self._append("GENESIS", {"message":"Cloud Attack Detection Ledger"})

    def _hash(self, index, timestamp, event_type, payload, previous_hash):
        raw=json.dumps({"index":index,"timestamp":timestamp,"event_type":event_type,"payload":payload,"previous_hash":previous_hash}, sort_keys=True, separators=(",",":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def _append(self, event_type, payload):
        idx=len(self.blocks); ts=time.time(); prev=self.blocks[-1]["hash"] if self.blocks else "0"*64
        block={"index":idx,"timestamp":ts,"event_type":event_type,"payload":payload,"previous_hash":prev}
        block["hash"]=self._hash(idx,ts,event_type,payload,prev); self.blocks.append(block); return block

    def append(self, event_type, payload): return self._append(event_type,payload)
    def verify(self):
        for i,b in enumerate(self.blocks):
            prev="0"*64 if i==0 else self.blocks[i-1]["hash"]
            if b["previous_hash"]!=prev or b["hash"]!=self._hash(b["index"],b["timestamp"],b["event_type"],b["payload"],b["previous_hash"]): return False
        return True
