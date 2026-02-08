# Deploy API Key Automaton

## Quick Start - Railway (Recommended)

```bash
# 1. Install Railway CLI
npm i -g @railway/cli

# 2. Login
railway login

# 3. Initialize and deploy
railway init
railway up

# 4. Set environment variables
railway variables set ADMIN_API_KEY=$(openssl rand -hex 32)

# 5. Get your deployment URL
railway open
```

## Alternative: Render

1. Connect GitHub repo to Render
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `python key_automaton.py`
4. Add Environment Variable: `ADMIN_API_KEY=your-secure-key`

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set admin key
export ADMIN_API_KEY="your-secret-key"

# Run service
python key_automaton.py

# Test it
curl http://localhost:8000/health
```

## Docker

```bash
# Build
docker build -t api-key-automaton .

# Run
docker run -p 8000:8000 -e ADMIN_API_KEY=secret api-key-automaton
```

## API Usage

### List all keys
```bash
curl -H "x-admin-api-key: YOUR_KEY" https://your-app.up.railway.app/keys
```

### Create a key
```bash
curl -X POST -H "x-admin-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"system_name":"Redis","system_type":"cache","env":"prod","name":"Redis Prod","key_ref":"vault://redis-prod"}' \
  https://your-app.up.railway.app/keys
```

### Rotate a key
```bash
curl -X POST -H "x-admin-api-key: YOUR_KEY" \
  https://your-app.up.railway.app/keys/key-001/rotate
```

## Next Steps

- Configure your vault (AWS Secrets Manager, HashiCorp Vault, etc.)
- Set up automated rotation schedules
- Connect to your CI/CD pipeline
- Add database persistence (PostgreSQL/Supabase)
