# LemonSqueezy Payment Integration Setup Guide

## Overview
This application uses LemonSqueezy for payment processing. Follow these steps to complete the configuration.

## Step 1: Create LemonSqueezy Account
1. Go to https://www.lemonsqueezy.com/
2. Sign up for an account
3. Complete account verification

## Step 2: Create Your Product
1. Log in to https://app.lemonsqueezy.com/
2. Go to **Products** > **Create Product**
3. Set up your product:
   - **Name**: "PULLEDOUT.LOL Access"
   - **Description**: "One-time payment for lifetime access"
   - **Price**: $50.00 USD
   - **Product Type**: Digital
4. Create a **Variant** (this is what customers purchase)
5. **Important**: Copy the **Variant ID** (not the Product ID) - you'll need this for LEMONSQUEEZY_PRODUCT_ID

## Step 3: Get Your Store ID
1. In LemonSqueezy dashboard, go to **Settings** > **Store**
2. Your Store ID is displayed on this page
3. Or check the URL: `https://app.lemonsqueezy.com/stores/YOUR_STORE_ID`
4. Copy this number for LEMONSQUEEZY_STORE_ID

## Step 4: Get Your Store URL
1. Go to **Settings** > **Store**
2. Find your public store URL (e.g., `https://yourstore.lemonsqueezy.com`)
3. Copy this for LEMONSQUEEZY_STORE_URL

## Step 5: Generate API Key
1. Go to **Settings** > **API**
2. Click **Create API Key**
3. Name it: "PULLEDOUT.LOL Backend"
4. Copy the generated API key (you won't see it again!)
5. Use this for LEMONSQUEEZY_API_KEY

## Step 6: Configure Webhook
1. Go to **Settings** > **Webhooks**
2. Click **Create Webhook**
3. Set the webhook URL to: `https://pulledout.lol/api/payment/webhook`
4. Select events to listen for:
   - ✅ `order_created`
   - ✅ `order_refunded` (optional)
5. Save the webhook
6. **Optional**: Copy the signing secret for webhook verification (not yet implemented)

## Step 7: Update .env File
Open your `.env` file and update these values:

```env
# LemonSqueezy Configuration
LEMONSQUEEZY_API_KEY=your_actual_api_key_here
LEMONSQUEEZY_STORE_URL=https://yourstore.lemonsqueezy.com
LEMONSQUEEZY_STORE_ID=12345
LEMONSQUEEZY_PRODUCT_ID=67890
```

**Important Notes:**
- Replace `your_actual_api_key_here` with your real API key
- Use the **Variant ID**, not the Product ID
- Store ID and Product ID are numbers only (no quotes)

## Step 8: Test the Integration
1. Restart your Flask server
2. Visit https://pulledout.lol/pay
3. Click "Purchase Access Now"
4. You should be redirected to LemonSqueezy checkout
5. Complete a test purchase (use test mode if available)

## Step 9: Verify Webhook
1. After a test purchase, check your Flask logs
2. You should see: `Payment received for Discord ID: [user_id]`
3. Check LemonSqueezy webhook logs in dashboard to verify delivery

## Current Flow
1. User clicks "Purchase Access Now" button
2. Backend creates checkout session via LemonSqueezy API
3. User redirected to LemonSqueezy checkout page
4. User completes payment
5. LemonSqueezy sends webhook to `/api/payment/webhook`
6. Backend logs the payment (TODO: assign Discord role, send invite)

## TODO: Complete Integration
The following features still need to be implemented:

### 1. Store Payments in Database
Create a `payments` table to track transactions:
```sql
CREATE TABLE payments (
    id INTEGER PRIMARY KEY,
    order_id TEXT UNIQUE,
    discord_id TEXT,
    amount INTEGER,
    currency TEXT,
    status TEXT,
    created_at TIMESTAMP
);
```

### 2. Generate Discord Invite
After successful payment:
- Use Discord bot to create a single-use, 48-hour invite link
- Store the invite code linked to the purchase

### 3. Send Invite to Customer
- Get customer email from LemonSqueezy order data
- Send automated email with Discord invite link
- Or send DM via Discord bot if user is already in server

### 4. Automatic Role Assignment
When user joins via invite:
- Discord bot detects new member
- Checks if they joined via paid invite
- Assigns buyer role (1484996965195579503)
- Sends welcome message

### 5. Webhook Security
Implement signature verification:
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

### 6. Refund Handling
Add refund webhook handler:
- Listen for `order_refunded` event
- Revoke Discord access (remove buyer role, add M.U role)
- Ban user from server if needed

## Troubleshooting

### "Payment system not configured" Error
- Check that all LEMONSQUEEZY_* variables are set in .env
- Restart Flask server after updating .env
- Verify values are correct (no extra spaces or quotes)

### Checkout URL Not Generated
- Check Flask logs for API errors
- Verify API key is valid and has correct permissions
- Ensure Store ID and Product ID (Variant ID) are correct
- Check LemonSqueezy API status

### Webhook Not Received
- Verify webhook URL in LemonSqueezy dashboard
- Check that your server is publicly accessible
- Test webhook using LemonSqueezy's "Send Test" button
- Check Flask logs for webhook processing errors

### User Still Redirected to /pay After Payment
- Check webhook is being received and processed
- Verify Discord ID is being stored with order
- Ensure role assignment is working
- User may need to log out and log back in

## Support
- LemonSqueezy Docs: https://docs.lemonsqueezy.com/
- LemonSqueezy API: https://docs.lemonsqueezy.com/api
- Discord Bot Guide: https://discord.com/developers/docs/

## Security Notes
- Never commit your .env file to Git
- Keep API keys secure
- Use webhook signature verification in production
- Implement rate limiting on payment endpoints
- Log all payment transactions for auditing
