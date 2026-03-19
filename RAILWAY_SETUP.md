# Railway Volume Setup Guide

## Configure Persistent Storage for SQLite

To ensure your data persists across deployments on Railway, you need to create a volume.

### Steps:

1. **Go to your Railway dashboard**: https://railway.app
2. **Select your pulledout.lol project**
3. **Click on your service** (web deployment)
4. **Go to the "Volumes" tab**
5. **Click "New Volume"**
6. **Configure the volume:**
   - **Name**: `database` (or any name you prefer)
   - **Mount Path**: `/data`
   - **Size**: Start with 1GB (increase if needed)
7. **Click "Create Volume"**
8. **Railway will automatically redeploy** with the volume attached

### What This Does:

- Creates a persistent volume at `/data` in your container
- The SQLite database (`sawsap.db`) is stored in `/data/`
- Data will **persist across deployments and restarts**
- No more lost user accounts or scan history

### Verify It's Working:

After deployment completes:
1. Visit your site: https://pulledout.lol
2. If you see a warning banner about database persistence, the volume isn't configured
3. If no warning appears, check Railway logs - you should see: `Using SQLite with persistent volume: /data/sawsap.db`

### Alternative: Use PostgreSQL (Recommended)

For production sites, PostgreSQL is preferred:

1. **Go to Railway dashboard**
2. **Click "New" → "Database" → "Add PostgreSQL"**
3. Railway automatically configures the `DATABASE_URL` environment variable
4. Your app will automatically use PostgreSQL instead of SQLite
5. Better performance, reliability, and scalability

### Current Configuration:

- **Volume mount**: `/data` (configured in `railway.json`)
- **Database path**: `/data/sawsap.db` (when volume is available)
- **Fallback**: Local SQLite if no volume or PostgreSQL is found

### Troubleshooting:

**Volume not mounting?**
- Check Railway service logs for errors
- Verify the mount path is exactly `/data`
- Ensure the volume is attached to the correct service

**Still losing data?**
- Check that `railway.json` is in the repository root
- Verify Railway is using the Dockerfile build (check build logs)
- Look for "Using SQLite with persistent volume" in deployment logs

**Need help?**
- Railway Discord: https://discord.gg/railway
- Railway Docs: https://docs.railway.app/reference/volumes
