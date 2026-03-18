// Signup Page JavaScript

document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const termsChecked = document.getElementById('termsCheckbox').checked;
    const errorDiv = document.getElementById('errorMessage');
    const successDiv = document.getElementById('successMessage');
    const signupBtn = document.getElementById('signupBtn');
    const btnText = signupBtn.querySelector('.btn-text');
    const btnLoader = signupBtn.querySelector('.btn-loader');
    
    // Hide previous messages
    errorDiv.classList.remove('show');
    successDiv.classList.remove('show');
    errorDiv.textContent = '';
    successDiv.textContent = '';
    
    // Validate password match
    if (password !== confirmPassword) {
        errorDiv.textContent = 'Passwords do not match';
        errorDiv.classList.add('show');
        return;
    }
    
    // Validate terms
    if (!termsChecked) {
        errorDiv.textContent = 'Please agree to the Terms of Service';
        errorDiv.classList.add('show');
        return;
    }
    
    // Disable button
    signupBtn.disabled = true;
    btnText.classList.add('hidden');
    btnLoader.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/auth/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Show success message
            successDiv.textContent = 'Account created! Redirecting to login...';
            successDiv.classList.add('show');
            
            // Redirect to login after 2 seconds
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            // Show error
            errorDiv.textContent = data.error || 'Signup failed';
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

// Auto-focus username field
document.getElementById('username').focus();

// Password match indicator
document.getElementById('confirmPassword').addEventListener('input', function() {
    const password = document.getElementById('password').value;
    const confirmPassword = this.value;
    
    if (confirmPassword && password !== confirmPassword) {
        this.style.borderColor = '#fc8181';
    } else if (confirmPassword) {
        this.style.borderColor = '#68d391';
    } else {
        this.style.borderColor = '#e2e8f0';
    }
});
