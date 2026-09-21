from __future__ import annotations
import tempfile, os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from backend.ml_engine import MLEngine, FEATURES
from backend.risk_engine import HierarchicalRisk
from backend.blockchain import Ledger

app=FastAPI(title="ML-Enhanced Blockchain Cloud Attack Detection API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
ml=MLEngine(); risk=HierarchicalRisk(); ledger=Ledger()

class DetectionInput(BaseModel):
    traffic_anomaly: float=Field(0.2, ge=0, le=1); cpu_usage: float=Field(.2,ge=0,le=1); memory_usage: float=Field(.2,ge=0,le=1)
    bandwidth_usage: float=Field(.2,ge=0,le=1); transaction_frequency: float=Field(.2,ge=0,le=1); security_incidents: float=Field(.1,ge=0,le=1)
    resource_distribution: float=Field(.2,ge=0,le=1); avg_resource_usage: float=Field(.2,ge=0,le=1); scalability_score: float=Field(.8,ge=0,le=1)
    node_degree: float=Field(.2,ge=0,le=1); centrality: float=Field(.2,ge=0,le=1)
    node_id: str="node-demo"; cluster: str="C1"

@app.get("/health")
def health(): return {"status":"ok","ledger_valid":ledger.verify()}

@app.get("/model")
def model_info(): return {"algorithm":"Random Forest","features":FEATURES,"metrics":ml.metrics,"training_source":ml.training_source}

@app.post("/predict")
def predict(x: DetectionInput):
    data=x.model_dump(); label,confidence,probs=ml.predict(data)
    signal={k:data[k] for k in FEATURES}
    rr=risk.assess(signal)
    block=ledger.append("ATTACK_DETECTION", {"node_id":x.node_id,"cluster":x.cluster,"prediction":label,"confidence":round(confidence,4),"risk":rr.risk,"level":rr.level})
    return {"prediction":label,"confidence":round(confidence,4),"probabilities":probs,"risk":rr.__dict__,"block":{"index":block["index"],"hash":block["hash"]}}

@app.post("/train")
async def train(file: UploadFile=File(...)):
    suffix=os.path.splitext(file.filename or ".csv")[1]
    if suffix.lower() != ".csv": raise HTTPException(400,"Upload a CSV file")
    with tempfile.NamedTemporaryFile(delete=False,suffix=suffix) as tmp:
        tmp.write(await file.read()); path=tmp.name
    try: ml.train_csv(path)
    except Exception as e: raise HTTPException(400,str(e))
    finally: os.unlink(path)
    ledger.append("MODEL_TRAINED", {"source":"uploaded-csv","metrics":ml.metrics})
    return {"message":"model retrained","metrics":ml.metrics}

@app.get("/ledger")
def get_ledger(): return {"valid":ledger.verify(),"blocks":list(reversed(ledger.blocks[-50:]))}

@app.post("/simulate")
def simulate():
    nodes=[]
    scenarios=[(.12,.18,"normal"),(.88,.91,"ddos"),(.68,.52,"suspicious"),(.45,.38,"probe")]
    for i,(ta,cpu,_) in enumerate(scenarios):
        nodes.append({"node_id":f"node-{i+1}","cluster":f"C{1+i%2}","signals":{"traffic_anomaly":ta,"cpu_usage":cpu,"memory_usage":min(1,cpu+.05),"bandwidth_usage":min(1,ta+.05),"security_incidents":ta*.8,"transaction_frequency":ta*.7,"resource_distribution":cpu,"avg_resource_usage":cpu,"scalability_score":1-cpu,"node_degree":.3,"centrality":.4}})
    n,c,g,t=risk.hierarchical(nodes)
    block=ledger.append("HIERARCHICAL_RISK_ASSESSMENT", {"nodes":n,"clusters":c,"global":g,"thresholds":t})
    return {"nodes":n,"clusters":c,"global":g,"thresholds":t,"block_index":block["index"]}
