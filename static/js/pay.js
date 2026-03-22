// Payment Page JavaScript

function getCookie(name) {
    const cookies = document.cookie.split(';');
    for (let c of cookies) {
        c = c.trim();
        if (c.startsWith(name + '=')) {
            return c.substring(name.length + 1);
        }
    }
    return null;
}

document.addEventListener('DOMContentLoaded', () => {
    const purchaseBtn = document.getElementById('purchaseBtn');
    
    if (!purchaseBtn) {
        console.error('Purchase button not found!');
        return;
    }
    
    purchaseBtn.addEventListener('click', async () => {
        console.log('Purchase button clicked');
        
        const errorDiv = document.getElementById('errorMessage');
        const btnText = purchaseBtn.querySelector('.btn-text');
        const btnLoader = purchaseBtn.querySelector('.btn-loader');
        
        // Hide previous errors
        errorDiv.classList.remove('show');
        errorDiv.textContent = '';
        
        // Disable button
        purchaseBtn.disabled = true;
        btnText.classList.add('hidden');
        btnLoader.classList.remove('hidden');
        
        try {
            // Get session token from cookie or localStorage (if available, send as header too)
            const sessionToken = getCookie('sessionToken') || localStorage.getItem('sessionToken');
            
            // Create checkout session - cookie is sent automatically by browser
            console.log('Creating checkout session...');
            console.log('Session token present:', !!sessionToken);
            
            const headers = { 'Content-Type': 'application/json' };
            if (sessionToken) {
                headers['Authorization'] = sessionToken;
            }
            
            const response = await fetch('/api/payment/create-checkout', {
                method: 'POST',
                headers: headers,
                credentials: 'same-origin'
            });
            
            console.log('Response status:', response.status);
            
            if (response.status === 401) {
                // Not logged in - go straight to Discord OAuth
                console.log('Not authenticated - redirecting to Discord OAuth...');
                const loginResp = await fetch('/api/auth/discord/login?next=/pay');
                const loginData = await loginResp.json();
                console.log('Discord OAuth URL:', loginData.auth_url ? 'received' : 'missing');
                
                if (loginData.auth_url) {
                    // Redirect to Discord for authentication
                    window.location.href = loginData.auth_url;
                } else {
                    // Fallback to login page if OAuth not configured
                    console.error('Discord OAuth not configured');
                    errorDiv.textContent = 'Authentication system not configured. Please contact support.';
                    errorDiv.classList.add('show');
                    purchaseBtn.disabled = false;
                    btnText.classList.remove('hidden');
                    btnLoader.classList.add('hidden');
                }
                return;
            }
            
            const data = await response.json();
            console.log('Response data:', data);
            
            if (response.ok && data.checkout_url) {
                // Redirect to LemonSqueezy checkout page
                console.log('Redirecting to LemonSqueezy checkout...');
                window.location.href = data.checkout_url;
            } else {
                // Show error message
                console.error('Checkout failed:', data);
                errorDiv.textContent = data.error || 'Failed to create checkout session';
                errorDiv.classList.add('show');
                
                // Re-enable button
                purchaseBtn.disabled = false;
                btnText.classList.remove('hidden');
                btnLoader.classList.add('hidden');
            }
        } catch (error) {
            // Network or unexpected error
            console.error('Payment error:', error);
            errorDiv.textContent = 'Network error. Please try again.';
            errorDiv.classList.add('show');
            
            // Re-enable button
            purchaseBtn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoader.classList.add('hidden');
        }
    });
});
