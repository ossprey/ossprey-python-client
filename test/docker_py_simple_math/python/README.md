# Safe Solana Transfer Service

A minimal FastAPI service that can send SOL transfers on Solana via a simple HTTP API.

Endpoints:
- GET /health – liveness check
- POST /transfer – send SOL from the configured signer to a recipient

Request body for /transfer:
```json
{
	"to_pubkey": "RecipientBase58Pubkey",
	"lamports": 10000,
	"memo": "optional"
}
```

Environment variables:
- SOLANA_RPC_URL (default: https://api.devnet.solana.com)
- WALLET_KEYPAIR_PATH – path in the container to a JSON keypair file (Solana CLI format)
- SOLANA_PRIVATE_KEY – JSON array string of 64 integers (secret key)

Notes:
- Use Devnet for testing. Fund your wallet via https://faucet.solana.com
- Handle secrets securely; avoid hardcoding private keys.

## Build Docker Image
```
docker build -t safe-python-app .
```

## Run Docker Container (Devnet)
```
docker run --rm -p 8000:8000 \
	-e SOLANA_RPC_URL=https://api.devnet.solana.com \
	-e SOLANA_PRIVATE_KEY='[1,2,3,...,64 ints...]' \
	safe-python-app
```

## Quick Test
```
curl -s http://localhost:8000/health

curl -s -X POST http://localhost:8000/transfer \
	-H 'Content-Type: application/json' \
	-d '{"to_pubkey":"<RECIPIENT>","lamports":10000}'
```
