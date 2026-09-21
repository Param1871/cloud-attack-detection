# CloudSentinel AI

Machine Learning-Enhanced Blockchain-Based Cloud Attack Detection using Random Forest and Hierarchical Risk Assessment.

## Architecture

Browser/Next.js dashboard → FastAPI ML service → Random Forest detection → DST-inspired hierarchical risk engine (node/cluster/global) → append-only SHA-256 ledger → optional Supabase persistence.

The supplied research reference describes a three-level risk model, dynamic thresholds, blockchain recording, and cloud simulation. It also describes attributes such as traffic anomalies, CPU/memory/resource usage, bandwidth, transaction frequency, historical incidents, graph centrality, and scalability. This prototype implements those ideas in a smaller demonstrable system.

## Run locally

```bash
docker compose up --build
```

Open http://localhost:3000 and API docs at http://localhost:8000/docs.

Without Docker:

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload
```

Then in another terminal:

```bash
cd frontend
npm install
npm run dev
```

## Dataset training

The demo starts with synthetic data so the UI works immediately. For a research evaluation, upload a CSV containing the 11 feature columns and `label`, then call `POST /train` or add a file-upload UI. Do not report the synthetic demo accuracy as experimental evidence.

## Cloud deployment plan

- Vercel: Next.js dashboard.
- Render: FastAPI/Random Forest service.
- Supabase: detection-event metadata, model runs, users, and audit references.
- Blockchain layer: for the academic prototype, the included ledger is a permissioned hash-chain abstraction. For a full blockchain implementation, replace it with Hyperledger Fabric smart contracts/chaincode or an Ethereum-compatible test network.

## Research evaluation

Use approved real datasets (for example CIC-IDS2017/CIC-DDoS2019), train/test without leakage, and report accuracy, precision, recall, F1, FPR, FNR, attack detection rate, packet loss, detection time, mitigation latency, ledger transaction latency, and resource usage.
