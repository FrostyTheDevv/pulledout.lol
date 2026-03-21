// Payment Page JavaScript

document.getElementById('purchaseBtn').addEventListener('click', async () => {
    const errorDiv = document.getElementById('errorMessage');
    const purchaseBtn = document.getElementById('purchaseBtn');
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
        // Get session token from localStorage
        const sessionToken = localStorage.getItem('sessionToken');
        
        if (!sessionToken) {
            // User not logged in - redirect to login
            window.location.href = '/login';
            return;
        }
        
        // Create checkout session with LemonSqueezy
        const response = await fetch('/api/payment/create-checkout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': sessionToken
            }
        });
        
        const data = await response.json();
        
        if (response.status === 401) {
            // Session expired - redirect to login
            window.location.href = '/login';
            return;
        }
        
        if (response.ok && data.checkout_url) {
            // Redirect to LemonSqueezy checkout page
            window.location.href = data.checkout_url;
        } else {
            // Show error message
            errorDiv.textContent = data.error || 'Failed to create checkout session';
            errorDiv.classList.add('show');
            
            // Re-enable button
            purchaseBtn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoader.classList.add('hidden');
        }
    } catch (error) {
        // Network or unexpected error
        errorDiv.textContent = 'Network error. Please try again.';
        errorDiv.classList.add('show');
        
        // Re-enable button
        purchaseBtn.disabled = false;
        btnText.classList.remove('hidden');
        btnLoader.classList.add('hidden');
    }
});
