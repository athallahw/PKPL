

import time

from django.shortcuts import redirect


SESSION_TIMEOUT = 1800
def add_security_headers(response):
    """Add security headers to response"""
    # Content Security Policy
    response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    
    # Prevent MIME sniffing
    response['X-Content-Type-Options'] = 'nosniff'
    
    # XSS protection
    response['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer policy
    response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Frame options
    response['X-Frame-Options'] = 'DENY'
    
    return response

class SecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check for session fixation
        if 'user_id' in request.session and not request.session.get('session_rotated'):
            request.session.cycle_key()
            request.session['session_rotated'] = True
            
        # Check for session timeout
        if 'authenticated_at' in request.session:
            last_activity = request.session.get('authenticated_at')
            if time.time() - last_activity > SESSION_TIMEOUT:
                # Session expired, log user out
                for key in list(request.session.keys()):
                    del request.session[key]
                return redirect('auth:sign_in')
            else:
                # Update activity timestamp
                request.session['authenticated_at'] = time.time()
                
        response = self.get_response(request)
        
        # Add security headers to all responses
        add_security_headers(response)
        
        return response