from flask import Flask, request, jsonify, render_template, Response
from email_verifier import EmailVerifier
from quick_email_verifier import QuickEmailVerifier
from rate_limiter import rate_limiter
from functools import wraps
import time
import logging
from logging.handlers import RotatingFileHandler
import traceback
import os
import csv
from io import StringIO
from config import (
    FLASK_CONFIG,
    LOG_CONFIG,
    DNS_CONFIG,
    SMTP_CONFIG,
    ERROR_MESSAGES
)

# Initialize Flask app
app = Flask(__name__)

# Configure logging
handler = RotatingFileHandler(
    LOG_CONFIG['FILENAME'],
    maxBytes=LOG_CONFIG['MAX_BYTES'],
    backupCount=LOG_CONFIG['BACKUP_COUNT']
)
handler.setFormatter(logging.Formatter(LOG_CONFIG['LOG_FORMAT']))
handler.setLevel(LOG_CONFIG['LOG_LEVEL'])
app.logger.addHandler(handler)
app.logger.setLevel(LOG_CONFIG['LOG_LEVEL'])

# Initialize verifiers
quick_verifier = QuickEmailVerifier()
detailed_verifier = EmailVerifier()

def rate_limit_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get client IP
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        # Get domain from email (if present in request)
        domain = ''
        if request.is_json and 'email' in request.json:
            try:
                domain = request.json['email'].split('@')[1]
            except:
                domain = 'invalid-domain'
        elif request.files and 'file' in request.files:
            domain = 'batch-validation'

        # Check rate limits
        allowed, limit_type, retry_after = rate_limiter.check_rate_limit(domain, ip)

        if not allowed:
            # Get remaining quotas for response
            quotas = rate_limiter.get_remaining_quota(domain, ip)

            response = {
                'error': ERROR_MESSAGES['RATE_LIMIT'],
                'limit_type': limit_type,
                'retry_after': int(retry_after),
                'quotas': quotas
            }

            headers = {
                'X-RateLimit-Retry-After': str(int(retry_after)),
                'X-RateLimit-Reset': str(int(time.time() + retry_after)),
            }

            app.logger.warning(f"Rate limit exceeded - Type: {limit_type}, IP: {ip}, Domain: {domain}")
            return jsonify(response), 429, headers

        # Add rate limit headers to response
        def add_headers(response):
            quotas = rate_limiter.get_remaining_quota(domain, ip)

            for limit_type, quota in quotas.items():
                response.headers[f'X-RateLimit-{limit_type.title()}-Remaining'] = str(quota['remaining_requests'])
                response.headers[f'X-RateLimit-{limit_type.title()}-Reset'] = str(int(time.time() + quota['window_remaining']))

            return response

        # Call the original route function
        response = f(*args, **kwargs)

        # Add headers to response
        if isinstance(response, tuple):
            response = (add_headers(response[0]), *response[1:])
        else:
            response = add_headers(response)

        return response

    return decorated_function

@app.route('/')
def home():
    """Render the home page"""
    return render_template('index.html')

@app.route('/upload')
def upload():
    """Render the CSV upload form"""
    return render_template('upload.html')

@app.route('/validate', methods=['POST'])
@rate_limit_handler
def validate():
    """Email validation endpoint with rate limiting"""
    try:
        email = request.json.get('email')
        validation_type = request.json.get('type', 'quick')

        if not email:
            return jsonify({'error': ERROR_MESSAGES['INVALID_EMAIL']}), 400

        app.logger.info(f"Starting {validation_type} validation for email: {email}")
        start_time = time.time()

        if validation_type == 'quick':
            try:
                domain = email.split('@')[1]
                # Get domain info first with detailed validation
                domain_info = quick_verifier._validate_domain_enhanced(domain)
                # Verify email with careful catch-all check
                smtp_info = {'is_valid': False, 'mx_info': {}}
                if domain_info['is_valid'] and domain_info['mx_records']:
                    # First check if the actual email exists
                    smtp_info = quick_verifier._verify_smtp_enhanced(email, domain_info['mx_records'])
                    # Only do catch-all test if the email exists
                    if smtp_info['is_valid']:
                        # Test with a definitely non-existent email
                        test_email = f"nonexistent_{int(time.time())}@{domain}"
                        test_result = quick_verifier._verify_smtp_enhanced(test_email, domain_info['mx_records'])
                        domain_info['is_catch_all'] = test_result['is_valid']
                    else:
                        domain_info['is_catch_all'] = False
                # Then verify email for additional checks
                result = quick_verifier.verify_email(email)

                # Update result status based on catch-all status
                if domain_info['is_catch_all']:
                    result.status = "Valid - But Catch-all (Use Caution)"
                elif result.is_valid:
                    result.status = "Valid - OK to Send"

                response_data = {
                    'is_valid': result.is_valid,
                    'format_valid': result.format_valid,
                    'domain_valid': domain_info['is_valid'],
                    'mailbox_exists': smtp_info['is_valid'],
                    'is_role_account': result.is_role_account,
                    'is_disposable': result.is_disposable,
                    'is_catch_all': domain_info['is_catch_all'],
                    'is_free_email': result.is_free_email,
                    'is_honeypot': result.is_honeypot,
                    'has_valid_syntax': result.has_valid_syntax,
                    'has_parked_mx': domain_info['is_parked'],
                    'has_valid_smtp': smtp_info['is_valid'],
                    'verification_time': result.verification_time,
                    'status': result.status,
                    'details': result.details,
                    'suggestions': result.suggestions,
                    'mx_info': smtp_info['mx_info'],
                    'domain_info': domain_info
                }
            except Exception as e:
                app.logger.error(f"Error in quick verification: {str(e)}\n{traceback.format_exc()}")
                return jsonify({
                    'error': str(e),
                    'status': 'Error'
                }), 500

            return jsonify(response_data)
        else:
            try:
                result = detailed_verifier.verify_email(email)
                response_data = {
                    'is_valid': result.is_valid,
                    'format_valid': result.format_valid,
                    'syntax_checks': result.syntax_checks,
                    'mx_check': {
                        'has_valid_mx': result.mx_check.has_valid_mx,
                        'mx_records': result.mx_check.mx_records,
                        'response_time': result.mx_check.response_time,
                        'accepts_all': result.mx_check.accepts_all,
                        'has_catch_all': result.mx_check.has_catch_all,
                        'port_open': result.mx_check.port_open
                    },
                    'smtp_check': result.smtp_check,
                    'is_disposable': result.is_disposable,
                    'is_role_account': result.is_role_account,
                    'is_free_email': result.is_free_email,
                    'dns_security': result.dns_security.__dict__,
                    'security_checks': result.security_checks.__dict__,
                    'suggestions': result.suggestions,
                    'score': result.score.__dict__,
                    'total_time': time.time() - start_time
                }
            except Exception as e:
                app.logger.error(f"Error in detailed verification: {str(e)}\n{traceback.format_exc()}")
                return jsonify({
                    'error': str(e),
                    'score': {
                        'score': 0,
                        'verdict': 'Error',
                        'details': [str(e)],
                        'confidence': 'None',
                        'verification_time': 0
                    }
                }), 500

            app.logger.info(f"Completed {validation_type} validation for {email} in {time.time() - start_time:.2f}s")
            return jsonify(response_data)

    except Exception as e:
        app.logger.error(f"Error validating email {email if email else 'unknown'}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'error': str(e),
            'score': {
                'score': 0,
                'verdict': 'Error',
                'details': [str(e)],
                'confidence': 'None',
                'verification_time': 0
            }
        }), 500

@app.route('/validate-csv', methods=['POST'])
@rate_limit_handler
def validate_csv():
    """CSV batch validation endpoint with rate limiting"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'Please upload a CSV file'}), 400

        # Read and validate CSV
        csv_content = StringIO(file.stream.read().decode("UTF-8"))
        csv_reader = csv.DictReader(csv_content)

        # Find the email column (case-insensitive)
        header_mapping = {header.lower(): header for header in csv_reader.fieldnames} if csv_reader.fieldnames else {}
        email_header = next((orig_header for header, orig_header in header_mapping.items() if header == 'email'), None)

        if not email_header:
            return jsonify({'error': 'CSV must contain an "email" column'}), 400

        results = []
        total_processed = 0
        start_time = time.time()

        for row in csv_reader:
            email = row[email_header].strip()  # Use the original header name
            try:
                domain = email.split('@')[1]
                # Get domain info first with detailed validation
                domain_info = quick_verifier._validate_domain_enhanced(domain)

                # Verify email with careful catch-all check
                smtp_info = {'is_valid': False, 'mx_info': {}}
                if domain_info['is_valid'] and domain_info['mx_records']:
                    smtp_info = quick_verifier._verify_smtp_enhanced(email, domain_info['mx_records'])
                    if smtp_info['is_valid']:
                        test_email = f"nonexistent_{int(time.time())}@{domain}"
                        test_result = quick_verifier._verify_smtp_enhanced(test_email, domain_info['mx_records'])
                        domain_info['is_catch_all'] = test_result['is_valid']
                    else:
                        domain_info['is_catch_all'] = False

                result = quick_verifier.verify_email(email)

                # Update result status based on catch-all status
                if domain_info['is_catch_all']:
                    result.status = "Valid - But Catch-all (Use Caution)"
                elif result.is_valid:
                    result.status = "Valid - OK to Send"

                results.append({
                    'email': email,
                    'validation_results': {
                        'format_valid': result.format_valid,
                        'domain_valid': domain_info['is_valid'],
                        'mailbox_exists': smtp_info['is_valid'],
                        'smtp_valid': result.has_valid_smtp,
                    },
                    'domain_configuration': {
                        'mx_records_found': bool(domain_info['mx_records']),
                        'catch_all_domain': domain_info['is_catch_all'],
                        'parked_domain': domain_info['is_parked'],
                    },
                    'security_checks': {
                        'role_account': result.is_role_account,
                        'disposable_email': result.is_disposable,
                        'free_provider': result.is_free_email,
                        'spam_trap': result.is_honeypot,
                    },
                    'status': result.status,
                    'verification_time': result.verification_time
                })
                total_processed += 1

            except Exception as e:
                app.logger.error(f"Error processing email {email}: {str(e)}\n{traceback.format_exc()}")
                results.append({
                    'email': email,
                    'error': str(e),
                    'status': 'Error'
                })

        # Create CSV response
        output = StringIO()
        fieldnames = ['email', 
                     'format_valid', 'domain_valid', 'mailbox_exists', 'smtp_valid',
                     'mx_records_found', 'catch_all_domain', 'parked_domain',
                     'role_account', 'disposable_email', 'free_provider', 'spam_trap',
                     'status', 'verification_time']

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            if 'error' in result:
                flat_result = {
                    'email': result['email'],
                    'status': f"Error: {result['error']}"
                }
                flat_result.update({field: 'N/A' for field in fieldnames if field not in flat_result})
            else:
                flat_result = {
                    'email': result['email'],
                    'format_valid': result['validation_results']['format_valid'],
                    'domain_valid': result['validation_results']['domain_valid'],
                    'mailbox_exists': result['validation_results']['mailbox_exists'],
                    'smtp_valid': result['validation_results']['smtp_valid'],
                    'mx_records_found': result['domain_configuration']['mx_records_found'],
                    'catch_all_domain': result['domain_configuration']['catch_all_domain'],
                    'parked_domain': result['domain_configuration']['parked_domain'],
                    'role_account': result['security_checks']['role_account'],
                    'disposable_email': result['security_checks']['disposable_email'],
                    'free_provider': result['security_checks']['free_provider'],
                    'spam_trap': result['security_checks']['spam_trap'],
                    'status': result['status'],
                    'verification_time': result['verification_time']
                }
            writer.writerow(flat_result)

        # Log completion
        total_time = time.time() - start_time
        app.logger.info(f"Completed batch validation of {total_processed} emails in {total_time:.2f}s")

        # Return CSV file
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=validation_results_{int(time.time())}.csv',
                'Content-Type': 'text/csv'
            }
        )

    except Exception as e:
        app.logger.error(f"Error processing CSV: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
@rate_limit_handler
def health_check():
    """Health check endpoint with rate limiting"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/quota', methods=['GET'])
@rate_limit_handler
def get_quota():
    """Endpoint to check current rate limit quotas"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    domain = request.args.get('domain', 'example.com')

    quotas = rate_limiter.get_remaining_quota(domain, ip)
    return jsonify({
        'quotas': quotas,
        'ip': ip
    })

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}\n{traceback.format_exc()}')
    return jsonify({'error': 'Internal Server Error'}), 500

@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    app.logger.info("Starting Email Validation Service")
    app.run(
        host=FLASK_CONFIG['HOST'],
        port=FLASK_CONFIG['PORT'],
        debug=FLASK_CONFIG['DEBUG']
    )