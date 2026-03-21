// Signup Page JavaScript - Discord OAuth

document.getElementById('discordSignupBtn').addEventListener('click', async () => {
    const errorDiv = document.getElementById('errorMessage');
    const signupBtn = document.getElementById('discordSignupBtn');
    const btnText = signupBtn.querySelector('.btn-text');
    const btnLoader = signupBtn.querySelector('.btn-loader');
    
    // Hide previous errors
    errorDiv.classList.remove('show');
    errorDiv.textContent = '';
    
    // Disable button
    signupBtn.disabled = true;
    btnText.classList.add('hidden');
    btnLoader.classList.remove('hidden');
    
    try {
        // Get Discord OAuth URL from backend (same endpoint as login)
        const response = await fetch('/api/auth/discord/login');
        const data = await response.json();
        
        if (response.ok && data.auth_url) {
            // Redirect to Discord OAuth page
            window.location.href = data.auth_url;
        } else {
            errorDiv.textContent = data.error || 'Discord signup unavailable';
            errorDiv.classList.add('show');
            
            // Re-enable button
            signupBtn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoader.classList.add('hidden');
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
        errorDiv.classList.add('show');
        
        // Re-enable button
        signupBtn.disabled = false;
        btnText.classList.remove('hidden');
        btnLoader.classList.add('hidden');
    }
});
