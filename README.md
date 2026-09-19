# BlockNova

BlockNova is a deterministic wallet and contract reputation engine. Phase 1 runs entirely on local sample data and produces bounded, explainable evidence paths. It does not infer safety from missing data and does not use an LLM for detection or scoring.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
uvicorn app:app --reload
```

The API is available at `http://127.0.0.1:8000`. Analyze the malicious fixture with:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
  -d '{"address":"0x1111111111111111111111111111111111111111","chain":"ethereum"}'
```

The clean fixture is `0x4444444444444444444444444444444444444444`.

Live mode requires an Etherscan-compatible `ETHERSCAN_API_URL` and optionally `ETHERSCAN_API_KEY` in `.env` for complete address history. `ETHEREUM_RPC_URL` is used for contract identification, while `GOPLUS_API_URL` plus `GOPLUS_API_KEY` provide external security flags. `BLOCKNOVA_CACHE_PATH` controls the small JSON cache. `RPC_LOOKBACK_BLOCKS` remains available for the RPC-only fallback collector. Run a live analysis with:

```bash
python -m analyzer 0x0000000000000000000000000000000000000000 --live
```

Add `--debug` to print collection, signal, graph, path, and data-quality counters. Validate a live run with:

```bash
python3 scripts/validate_live.py 0x0000000000000000000000000000000000000000
```

The API accepts `{"live": true}` in the `/analyze` request. Provider failures and missing configuration lower `dataQuality` and appear in `limitations`; they are never treated as clean evidence.

## How the novelty works

1. BlockNova analyzes blockchain evidence.
2. Risk is calculated from that evidence.
3. The exact evidence records are cryptographically committed with a deterministic Merkle root.
4. Risk, evidence root, schema version, observation time, and expiry can be published as an EAS attestation.
5. Another smart contract can verify the reputation through a trusted registry and EAS.
6. No API call is required for the consuming contract.

The differentiating combination is the evidence graph, explainable propagation, portable cryptographic commitment, and contract-readable verification. A real EAS deployment is pending contract addresses and deployment credentials; the local registry/vault path is covered by tests and does not fabricate an on-chain UID.

## Delivery status

Phase 1 is local and deterministic: graph modeling, bounded traversal, exposure/hop/recency/edge weighting, correlation-aware aggregation, multidimensional risk, evidence validation, and API contracts are implemented. Phase 2.1 adds bounded Ethereum JSON-RPC collection and GoPlus signal normalization. Phase 2.3 adds cached Etherscan-compatible transaction, ERC-20 transfer, and Approval history plus contract identification. Optional narrative LLM rendering and EAS attestation remain deferred.
