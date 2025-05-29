from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import json
from datetime import datetime
from functools import wraps
import base64
from werkzeug.security import generate_password_hash, check_password_hash
# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize Firebase
# Decode credentials from environment variable if present
b64_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_B64")
if b64_creds:
    with open("job-portal.json", "wb") as f:
        f.write(base64.b64decode(b64_creds))
    cred_path = "job-portal.json"
else:
    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "job-portal.json")
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)

db = firestore.client()

# Authentication middleware
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
           
            # Verify the token
            decoded_token = auth.verify_id_token(token)
            user_id = decoded_token['uid']
            
            # Add user_id to kwargs
            kwargs['user_id'] = user_id
            
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Route for role-based access check
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = kwargs.get('user_id')
            print('user_id:', user_id)
            if not user_id:
                return jsonify({'message': 'User ID not found in token'}), 401
            
            try:
                # Get user document from Firestore
                user_ref = db.collection('users').document(user_id).get()
                if not user_ref.exists:
                    return jsonify({'message': 'User not found'}), 404
                
                user_data = user_ref.to_dict()
                user_role = user_data.get('role')
                
                if user_role not in roles:
                    return jsonify({'message': 'Unauthorized access'}), 403
                
                # Add user_role to kwargs
                kwargs['user_role'] = user_role
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'message': 'Error checking user role', 'error': str(e)}), 500
        
        return decorated_function
    return decorator


# Register endpoint
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        name = data.get('name', '')

        if not email or not password or not role:
            return jsonify({'message': 'Email, password, and role are required'}), 400

        if role not in ['admin', 'employer', 'jobseeker']:
            return jsonify({'message': 'Invalid role'}), 400

        # Create user in Firebase Auth
        user_record = auth.create_user(
            email=email,
            password=password,
            display_name=name
        )
        user_id = user_record.uid

        # Add user to Firestore
        user_data = {
            'email': email,
            'role': role,
            'name': name,
            'createdAt': datetime.now().timestamp() * 1000,
            'updatedAt': datetime.now().timestamp() * 1000,
        }
        db.collection('users').document(user_id).set(user_data)

        # Create custom token for client to exchange for ID token
        custom_token = auth.create_custom_token(user_id).decode('utf-8')

        return jsonify({'message': 'User registered successfully', 'token': custom_token, 'user': {'id': user_id, **user_data}})
    except Exception as e:
        print('Register error:', e)  # Add this for debugging
        return jsonify({'message': 'Error registering user', 'error': str(e)}), 500
# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400

        # Firebase Admin SDK does not support password verification directly.
        # You must use Firebase Client SDK on the frontend to sign in and get the ID token.
        # Here, we just check if the user exists and return an error if not.

        user = auth.get_user_by_email(email)
        user_id = user.uid

        # Get user data from Firestore
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'message': 'User not found'}), 404

        user_data = user_doc.to_dict()

        # Create custom token for client to exchange for ID token
        custom_token = auth.create_custom_token(user_id).decode('utf-8')

        return jsonify({'message': 'Login successful', 'token': custom_token, 'user': {'id': user_id, **user_data}})
    except Exception as e:
        print('loginerror',e)
        return jsonify({'message': 'Error logging in', 'error': str(e)}), 500


# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'API is running'})

# User routes
@app.route('/api/users', methods=['GET'])
@token_required
@role_required(['admin'])
def get_users(user_id, user_role):
    try:
        role = request.args.get('role')
        print('role:', role)
        limit_val = request.args.get('limit', default=100, type=int)
        
        users_ref = db.collection('users')
        
        if role:
            query = users_ref.where('role', '==', role).limit(limit_val)
        else:
            query = users_ref.limit(limit_val)
        
        users = [{'id': doc.id, **doc.to_dict()} for doc in query.stream()]
        print('users:', users) 
        return jsonify(users)
    except Exception as e:
        return jsonify({'message': 'Error fetching users', 'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['GET'])
@token_required
def get_user(user_id, **kwargs):
    request_user_id = kwargs.get('user_id')
    
    
    # Check if user is requesting their own data or is an admin
    if request_user_id != user_id:
        user_ref = db.collection('users').document(request_user_id).get()
        if not user_ref.exists or user_ref.to_dict().get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403
    
    try:
        user_ref = db.collection('users').document(user_id).get()
        if not user_ref.exists:
            return jsonify({'message': 'User not found'}), 404
        
        return jsonify({'id': user_ref.id, **user_ref.to_dict()})
    except Exception as e:
        return jsonify({'message': 'Error fetching user', 'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id, **kwargs):
    user_id = request.view_args['user_id'] 
    print('user_id:', user_id)
    request_user_id = request.view_args['user_id'] 
    print('request_user_id:', request_user_id)
    # Check if user is updating their own data or is an admin
    if request_user_id != user_id:
        user_ref = db.collection('users').document(request_user_id).get()
        if not user_ref.exists or user_ref.to_dict().get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403
    
    try:
        data = request.json
        
        # Don't allow changing role unless admin
        if 'role' in data and request_user_id != user_id:
            user_ref = db.collection('users').document(request_user_id).get()
            if not user_ref.exists or user_ref.to_dict().get('role') != 'admin':
                data.pop('role')
        
        # Update timestamp
        data['updatedAt'] = datetime.now().timestamp() * 1000
        
        user_ref = db.collection('users').document(user_id)
        user_ref.update(data)
        
        updated_user = user_ref.get()
        return jsonify({'id': updated_user.id, **updated_user.to_dict()})
    except Exception as e:
        return jsonify({'message': 'Error updating user', 'error': str(e)}), 500

# Job routes
@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    try:
        # Parse query parameters
        category = request.args.get('category')
        location = request.args.get('location')
        keyword = request.args.get('keyword')
        company = request.args.get('company')
        limit_val = request.args.get('limit', default=50, type=int)
        
        # Build query
        jobs_ref = db.collection('jobs').where('isActive', '==', True)
        
        # Apply filters
        if category:
            jobs_ref = jobs_ref.where('category', '==', category)
        
        if location:
            jobs_ref = jobs_ref.where('location', '==', location)
        
        if company:
            jobs_ref = jobs_ref.where('company', '==', company)
        
        # Get documents
        docs = jobs_ref.order_by('createdAt', direction='DESCENDING').limit(limit_val).stream()
        
        # Convert to list
        jobs = []
        for doc in docs:
            job_data = {'id': doc.id, **doc.to_dict()}
            
            # Apply keyword filter (client-side)
            if keyword:
                keyword = keyword.lower()
                title = job_data.get('title', '').lower()
                description = job_data.get('description', '').lower()
                
                if keyword in title or keyword in description:
                    jobs.append(job_data)
            else:
                jobs.append(job_data)
        
        return jsonify(jobs)
    except Exception as e:
        return jsonify({'message': 'Error fetching jobs', 'error': str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['GET'])
def get_job(job_id):
    try:
        job_ref = db.collection('jobs').document(job_id).get()
        
        if not job_ref.exists:
            return jsonify({'message': 'Job not found'}), 404
        
        return jsonify({'id': job_ref.id, **job_ref.to_dict()})
    except Exception as e:
        return jsonify({'message': 'Error fetching job', 'error': str(e)}), 500
    
@app.route('/api/users/<user_id>', methods=['DELETE'])
@token_required
@role_required(['admin'])
def delete_user(user_id, user_role):
    try:
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'message': 'User not found'}), 404

        # Soft delete: set role to 'deleted' and isActive to False
        user_ref.update({
            'role': 'deleted',
            'isActive': False,
            'updatedAt': datetime.now().timestamp() * 1000
        })

        return jsonify({'message': 'User deleted (soft delete) successfully'})
    except Exception as e:
        return jsonify({'message': 'Error deleting user', 'error': str(e)}), 500

@app.route('/api/jobs', methods=['POST'])
@token_required
@role_required(['employer', 'admin'])
def create_job(user_id, user_role):
    try:
        data = request.json
        
        # Set employer ID
        data['employerId'] = user_id
        
        # Set timestamps
        current_time = datetime.now().timestamp() * 1000
        data['createdAt'] = current_time
        data['updatedAt'] = current_time
        data['isActive'] = True
        data['applications'] = []
        
        # Create job document
        job_ref = db.collection('jobs').document()
        job_id = job_ref.id
        data['id'] = job_id
        job_ref.set(data)
        
        # Update employer's postedJobs array
        employer_ref = db.collection('users').document(user_id)
        employer_doc = employer_ref.get()
        
        if employer_doc.exists:
            employer_data = employer_doc.to_dict()
            posted_jobs = employer_data.get('postedJobs', [])
            posted_jobs.append(job_id)
            employer_ref.update({'postedJobs': posted_jobs})
        
        return jsonify({'id': job_id, **data})
    except Exception as e:
        return jsonify({'message': 'Error creating job', 'error': str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['PUT'])
@token_required
def update_job(job_id, user_id):
    try:
        job_ref = db.collection('jobs').document(job_id)
        job_doc = job_ref.get()
        
        if not job_doc.exists:
            return jsonify({'message': 'Job not found'}), 404
        
        job_data = job_doc.to_dict()
        
        # Check if user is the employer who posted the job or an admin
        if job_data.get('employerId') != user_id:
            user_ref = db.collection('users').document(user_id).get()
            if not user_ref.exists or user_ref.to_dict().get('role') != 'admin':
                return jsonify({'message': 'Unauthorized access'}), 403
        
        data = request.json
        
        # Don't allow changing employerId
        if 'employerId' in data:
            data.pop('employerId')
        
        # Update timestamp
        data['updatedAt'] = datetime.now().timestamp() * 1000
        
        job_ref.update(data)
        
        updated_job = job_ref.get()
        return jsonify({'id': updated_job.id, **updated_job.to_dict()})
    except Exception as e:
        return jsonify({'message': 'Error updating job', 'error': str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['DELETE'])
@token_required
def delete_job(job_id, user_id):
    try:
        job_ref = db.collection('jobs').document(job_id)
        job_doc = job_ref.get()
        
        if not job_doc.exists:
            return jsonify({'message': 'Job not found'}), 404
        
        job_data = job_doc.to_dict()
        
        # Check if user is the employer who posted the job or an admin
        if job_data.get('employerId') != user_id:
            user_ref = db.collection('users').document(user_id).get()
            if not user_ref.exists or user_ref.to_dict().get('role') != 'admin':
                return jsonify({'message': 'Unauthorized access'}), 403
        
        # Instead of deleting, set isActive to false
        job_ref.update({
            'isActive': False,
            'updatedAt': datetime.now().timestamp() * 1000
        })
        
        return jsonify({'message': 'Job deleted successfully'})
    except Exception as e:
        return jsonify({'message': 'Error deleting job', 'error': str(e)}), 500

from firebase_admin import storage

@app.route('/api/applications', methods=['POST'])
@token_required
@role_required(['jobseeker'])
def create_application(user_id, user_role):
    try:
        # For file uploads, use request.form and request.files
        data = dict(request.form)
        print('request.form:', request.form)
        print('request.files:', request.files)
        resume_file = request.files.get('resume')

        # Add cover letter if present
        data['coverLetter'] = data.get('coverLetter', '')

        # Set user ID
        data['userId'] = user_id

        # Check if job exists
        job_id = data.get('jobId')
        if not job_id:
            return jsonify({'message': 'Job ID is required'}), 400

        job_ref = db.collection('jobs').document(job_id).get()
        if not job_ref.exists:
            return jsonify({'message': 'Job not found'}), 404

        # Get job title
        job_data = job_ref.to_dict()
        data['jobTitle'] = job_data.get('title', '')

        # Check if user has already applied
        user_ref = db.collection('users').document(user_id).get()
        user_data = user_ref.to_dict()
        applied_jobs = user_data.get('appliedJobs', [])

        if job_id in applied_jobs:
            return jsonify({'message': 'You have already applied for this job'}), 400

        # Add user name/email
        data['userName'] = user_data.get('name', '')
        data['userEmail'] = user_data.get('email', '')

        

        # Set timestamps and status
        current_time = datetime.now().timestamp() * 1000
        data['appliedAt'] = current_time
        data['updatedAt'] = current_time
        data['status'] = 'pending'

        # Create application document
        application_ref = db.collection('applications').document()
        application_id = application_ref.id
        data['id'] = application_id
        application_ref.set(data)

        # Update job's applications array
        applications = job_data.get('applications', [])
        applications.append(application_id)
        db.collection('jobs').document(job_id).update({'applications': applications})

        # Update user's appliedJobs array
        applied_jobs.append(job_id)
        db.collection('users').document(user_id).update({'appliedJobs': applied_jobs})

        return jsonify({'id': application_id, **data})
    except Exception as e:
        print('Error in create_application:', e)
        return jsonify({'message': 'Error creating application', 'error': str(e)}), 500500
    

@app.route('/api/applications', methods=['GET'])
@token_required
def get_applications(user_id):
    try:
        # Parse query parameters
        job_id = request.args.get('jobId')
        status = request.args.get('status')
        
        # Get user role
        user_ref = db.collection('users').document(user_id).get()
        if not user_ref.exists:
            return jsonify({'message': 'User not found'}), 404
        
        user_data = user_ref.to_dict()
        user_role = user_data.get('role')
        
        # Build query based on role
        applications_ref = db.collection('applications')
        
        if user_role == 'jobseeker':
            # Job seekers can only see their own applications
            query = applications_ref.where('userId', '==', user_id)
        elif user_role == 'employer':
            # Employers can see applications for their jobs
            if job_id:
                # Check if job belongs to employer
                job_ref = db.collection('jobs').document(job_id).get()
                if not job_ref.exists:
                    return jsonify({'message': 'Job not found'}), 404
                
                job_data = job_ref.to_dict()
                if job_data.get('employerId') != user_id:
                    return jsonify({'message': 'Unauthorized access'}), 403
                
                query = applications_ref.where('jobId', '==', job_id)
            else:
                # Get employer's jobs
                employer_jobs = user_data.get('postedJobs', [])
                if not employer_jobs:
                    return jsonify([])
                
                # This is not efficient for large numbers of jobs
                # In a real app, you'd use a different data structure
                applications = []
                for job in employer_jobs:
                    job_applications = applications_ref.where('jobId', '==', job).stream()
                    for app in job_applications:
                        applications.append({'id': app.id, **app.to_dict()})
                
                # Apply status filter
                if status:
                    applications = [app for app in applications if app.get('status') == status]
                
                return jsonify(applications)
        elif user_role == 'admin':
            # Admins can see all applications
            if job_id:
                query = applications_ref.where('jobId', '==', job_id)
            else:
                query = applications_ref
        else:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Apply status filter
        if status:
            query = query.where('status', '==', status)
        
        # Get documents and convert to list
        applications = [{'id': doc.id, **doc.to_dict()} for doc in query.stream()]
        
        return jsonify(applications)
    except Exception as e:
        return jsonify({'message': 'Error fetching applications', 'error': str(e)}), 500

@app.route('/api/applications/<application_id>', methods=['GET'])
@token_required
def get_application(application_id, user_id):
    try:
        application_ref = db.collection('applications').document(application_id).get()
        
        if not application_ref.exists:
            return jsonify({'message': 'Application not found'}), 404
        
        application_data = application_ref.to_dict()
        
        # Check access permissions
        user_ref = db.collection('users').document(user_id).get()
        user_data = user_ref.to_dict()
        user_role = user_data.get('role')
        
        # Job seekers can only view their own applications
        if user_role == 'jobseeker' and application_data.get('userId') != user_id:
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Employers can only view applications for their jobs
        if user_role == 'employer':
            job_id = application_data.get('jobId')
            job_ref = db.collection('jobs').document(job_id).get()
            job_data = job_ref.to_dict()
            
            if job_data.get('employerId') != user_id:
                return jsonify({'message': 'Unauthorized access'}), 403
        
        # Admins can view all applications
        
        return jsonify({'id': application_ref.id, **application_data})
    except Exception as e:
        return jsonify({'message': 'Error fetching application', 'error': str(e)}), 500

@app.route('/api/applications/<application_id>', methods=['PUT'])
@token_required
def update_application_status(application_id, user_id):
    try:
        application_ref = db.collection('applications').document(application_id)
        application_doc = application_ref.get()
        
        if not application_doc.exists:
            return jsonify({'message': 'Application not found'}), 404
        
        application_data = application_doc.to_dict()
        
        # Get user role
        user_ref = db.collection('users').document(user_id).get()
        user_data = user_ref.to_dict()
        user_role = user_data.get('role')
        
        # Check permissions
        if user_role == 'jobseeker':
            # Job seekers can only update their own applications
            if application_data.get('userId') != user_id:
                return jsonify({'message': 'Unauthorized access'}), 403
            
            # Job seekers can only withdraw their applications
            data = request.json
            if data.get('status') != 'withdrawn':
                return jsonify({'message': 'Unauthorized action'}), 403
        elif user_role == 'employer':
            # Employers can only update applications for their jobs
            job_id = application_data.get('jobId')
            job_ref = db.collection('jobs').document(job_id).get()
            job_data = job_ref.to_dict()
            
            if job_data.get('employerId') != user_id:
                return jsonify({'message': 'Unauthorized access'}), 403
        
        # Update application
        data = request.json
        
        # Don't allow changing userId or jobId
        if 'userId' in data:
            data.pop('userId')
        
        if 'jobId' in data:
            data.pop('jobId')
        
        # Update timestamp
        data['updatedAt'] = datetime.now().timestamp() * 1000
        
        application_ref.update(data)
        
        updated_application = application_ref.get()
        return jsonify({'id': updated_application.id, **updated_application.to_dict()})
    except Exception as e:
        return jsonify({'message': 'Error updating application', 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
