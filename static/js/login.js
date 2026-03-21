// Login Page JavaScript

// Get CSRF token from hidden input or meta tag
function getCSRFToken() {
    // Try hidden input first
    const input = document.querySelector('input[name="csrf_token"]');
    if (input) return input.value;
    // Fallback to meta tag
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('errorMessage');
    const loginBtn = document.getElementById('loginBtn');
    const btnText = loginBtn.querySelector('.btn-text');
    const btnLoader = loginBtn.querySelector('.btn-loader');
    
    // Hide previous errors
    errorDiv.classList.remove('show');
    errorDiv.textContent = '';
    
    // Disable button
    loginBtn.disabled = true;
    btnText.classList.add('hidden');
    btnLoader.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCSRFToken()
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Store session token
            localStorage.setItem('sessionToken', data.session_token);
            localStorage.setItem('username', data.username);
            
            // Redirect to dashboard
            window.location.href = '/';
        } else {
            // Show error
            errorDiv.textContent = data.error || 'Login failed';
            errorDiv.classList.add('show');
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
        errorDiv.classList.add('show');
    } finally {
        // Re-enable button
        loginBtn.disabled = false;
        btnText.classList.remove('hidden');
        btnLoader.classList.add('hidden');
    }
});

// Auto-focus username field
document.getElementById('username').focus();
