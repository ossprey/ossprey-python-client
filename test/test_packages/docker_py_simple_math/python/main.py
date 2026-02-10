import json
import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from solana.rpc.api import Client
from solana.transaction import Transaction
from solders.system_program import transfer, TransferParams
from solders.pubkey import Pubkey
from solders.keypair import Keypair


class TransferRequest(BaseModel):
    to_pubkey: str = Field(..., description="Recipient public key (base58)")
    lamports: int = Field(..., gt=0, description="Amount in lamports to transfer")
    memo: Optional[str] = Field(None, description="Optional memo (not stored on-chain here)")


def load_signer() -> Keypair:
    """Load a signer Keypair from environment.

    Supports either WALLET_KEYPAIR_PATH (JSON array like Solana CLI) or
    SOLANA_PRIVATE_KEY (JSON array string of 64 integers).
    """
    keypair_path = os.getenv("WALLET_KEYPAIR_PATH")
    private_key_json = os.getenv("SOLANA_PRIVATE_KEY")

    if keypair_path and os.path.isfile(keypair_path):
        with open(keypair_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Invalid keypair file format; expected JSON array")
        return Keypair.from_bytes(bytes(data))

    if private_key_json:
        try:
            arr = json.loads(private_key_json)
            if not isinstance(arr, list):
                raise ValueError
            return Keypair.from_bytes(bytes(arr))
        except Exception as e:
            raise ValueError(f"Invalid SOLANA_PRIVATE_KEY: {e}") from e

    raise ValueError("No signer configured. Set WALLET_KEYPAIR_PATH or SOLANA_PRIVATE_KEY.")


def get_client() -> Client:
    rpc_url = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")
    return Client(rpc_url)


app = FastAPI(title="Safe Solana Transfer Service", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/transfer")
def post_transfer(req: TransferRequest):
    try:
        signer = load_signer()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    client = get_client()
    try:
        to_pubkey = Pubkey.from_string(req.to_pubkey)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid to_pubkey: {e}")

    ix = transfer(TransferParams(from_pubkey=signer.pubkey(), to_pubkey=to_pubkey, lamports=req.lamports))
    tx = Transaction().add(ix)

    # Recent blockhash fetched implicitly by send_transaction in newer solana-py,
    # but we handle both cases by trying a simple call.
    try:
        sig = client.send_transaction(tx, signer)["result"]
    except Exception:
        # Fallback for typed responses
        resp = client.send_transaction(tx, signer)
        if isinstance(resp, dict):
            sig = resp.get("result") or resp.get("result", {}).get("signature")
        else:
            raise

    if not sig:
        raise HTTPException(status_code=500, detail="Failed to send transaction")

    # Best-effort confirmation
    try:
        client.confirm_transaction(sig)
    except Exception:
        pass

    return {"signature": sig}


if __name__ == "__main__":
    # Optional: run a quick dev server when executed directly
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
