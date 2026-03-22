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
            // Get session token from cookie or localStorage
            const sessionToken = getCookie('sessionToken') || localStorage.getItem('sessionToken');
            console.log('Session token exists:', !!sessionToken);
            
            if (!sessionToken) {
                // User not logged in - redirect to login
                console.log('No session token, redirecting to login');
                window.location.href = '/login';
                return;
            }
            
            // Create checkout session with LemonSqueezy
            console.log('Creating checkout session...');
            const response = await fetch('/api/payment/create-checkout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': sessionToken
                }
            });
            
            console.log('Response status:', response.status);
            const data = await response.json();
            console.log('Response data:', data);
            
            if (response.status === 401) {
                // Session expired - redirect to login
                console.log('Session expired, redirecting to login');
                window.location.href = '/login';
                return;
            }
            
            if (response.ok && data.checkout_url) {
                // Redirect to LemonSqueezy checkout page
                console.log('Redirecting to checkout:', data.checkout_url);
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
