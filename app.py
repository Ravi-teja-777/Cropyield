import os
import boto3
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import uuid
from decimal import Decimal

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cropyield_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'CropYieldUsers')
FIELDS_TABLE_NAME = os.environ.get('FIELDS_TABLE_NAME', 'CropYieldFields')
YIELD_DATA_TABLE_NAME = os.environ.get('YIELD_DATA_TABLE_NAME', 'CropYieldData')
WEATHER_TABLE_NAME = os.environ.get('WEATHER_TABLE_NAME', 'CropYieldWeather')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
fields_table = dynamodb.Table(FIELDS_TABLE_NAME)
yield_data_table = dynamodb.Table(YIELD_DATA_TABLE_NAME)
weather_table = dynamodb.Table(WEATHER_TABLE_NAME)

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def send_sns_alert(message, subject):
    """Send SNS alert for crop anomalies"""
    if ENABLE_SNS and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=message,
                Subject=subject
            )
            return True
        except Exception as e:
            print(f"SNS Error: {e}")
            return False
    return False

def analyze_yield_anomaly(current_yield, historical_avg):
    """Check if current yield is significantly different from historical average"""
    if historical_avg == 0:
        return False, 0
    
    percentage_diff = ((current_yield - historical_avg) / historical_avg) * 100
    
    # Alert if yield is 20% below or above historical average
    if abs(percentage_diff) > 20:
        return True, percentage_diff
    return False, percentage_diff

def login_required(f):
    """Decorator for routes that require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator for admin-only routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def farmer_required(f):
    """Decorator for farmer-only routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'farmer':
            flash('Farmer access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

from boto3.dynamodb.conditions import Key

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'farmer')  # Default to farmer
        farm_name = data.get('farm_name', '')

        if not all([username, email, password]):
            flash('All fields are required')
            return render_template('register.html') if request.form else jsonify({'error': 'All fields required'}), 400

        # Check if user already exists using GSI query on email
        try:
            response = users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            if response.get('Count', 0) > 0:
                flash('User already exists')
                return render_template('register.html') if request.form else jsonify({'error': 'User exists'}), 409
        except Exception as e:
            print(f"Error checking existing user: {e}")
            flash('Database error')
            return render_template('register.html') if request.form else jsonify({'error': str(e)}), 500

        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)

        try:
            users_table.put_item(Item={
                'user_id': user_id,
                'email': email,
                'username': username,
                'password': hashed_password,
                'role': role,
                'farm_name': farm_name,
                'created_at': datetime.now().isoformat(),
                'is_active': True
            })

            flash('Registration successful')
            if request.form:
                return redirect(url_for('login'))
            else:
                return jsonify({'message': 'User created successfully', 'user_id': user_id}), 201

        except Exception as e:
            print(f"Error saving user to DynamoDB: {e}")
            flash('Registration failed')
            return render_template('register.html') if request.form else jsonify({'error': str(e)}), 500

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()

        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            flash('Email and password required')
            return render_template('login.html') if request.form else jsonify({'error': 'Missing credentials'}), 400

        try:
            response = users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            if response.get('Count', 0) == 0:
                flash('Invalid credentials')
                return render_template('login.html') if request.form else jsonify({'error': 'Invalid credentials'}), 401

            user = response['Items'][0]

            if not user.get('is_active', True):
                flash('Account deactivated')
                return render_template('login.html') if request.form else jsonify({'error': 'Account deactivated'}), 401

            if check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['user_role'] = user.get('role', 'farmer')
                session['farm_name'] = user.get('farm_name', '')

                if request.form:
                    return redirect(url_for('dashboard'))
                else:
                    return jsonify({
                        'message': 'Login successful',
                        'user': {
                            'user_id': user['user_id'],
                            'username': user['username'],
                            'email': user['email'],
                            'role': user.get('role', 'farmer')
                        }
                    }), 200
            else:
                flash('Invalid credentials')
                return render_template('login.html') if request.form else jsonify({'error': 'Invalid credentials'}), 401

        except Exception as e:
            print(f"Login error: {e}")
            flash('Login failed')
            return render_template('login.html') if request.form else jsonify({'error': str(e)}), 500

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('index'))

# ---------------------------------------
# Dashboard Routes
# ---------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_role = session.get('user_role', 'farmer')
    
    if user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('farmer_dashboard'))

@app.route('/farmer/dashboard')
@login_required
def farmer_dashboard():
    try:
        # Get farmer's fields
        fields_response = fields_table.query(
            IndexName='FarmerIndex',
            KeyConditionExpression='farmer_id = :farmer_id',
            ExpressionAttributeValues={':farmer_id': session['user_id']},
            Limit=10
        )
        fields = fields_response.get('Items', [])
        
        # Get recent yield data for farmer's fields
        recent_yields = []
        for field in fields:
            yield_response = yield_data_table.query(
                IndexName='FieldIndex',
                KeyConditionExpression='field_id = :field_id',
                ExpressionAttributeValues={':field_id': field['field_id']},
                Limit=5,
                ScanIndexForward=False
            )
            field_yields = yield_response.get('Items', [])
            recent_yields.extend(field_yields)
        
        # Sort by date
        recent_yields.sort(key=lambda x: x.get('harvest_date', ''), reverse=True)
        recent_yields = recent_yields[:10]  # Limit to 10 most recent
        
        return render_template('farmer_dashboard.html', 
                             fields=fields, 
                             recent_yields=recent_yields,
                             farm_name=session.get('farm_name', ''))
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}')
        return render_template('farmer_dashboard.html', fields=[], recent_yields=[])

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # Get all yield data for analysis
        yield_response = yield_data_table.scan(Limit=50)
        all_yields = yield_response.get('Items', [])
        
        # Get all fields
        fields_response = fields_table.scan()
        all_fields = fields_response.get('Items', [])
        
        # Calculate statistics
        total_fields = len(all_fields)
        total_yield_records = len(all_yields)
        
        # Calculate average yield by crop type
        crop_stats = {}
        for yield_record in all_yields:
            crop_type = yield_record.get('crop_type', 'Unknown')
            yield_amount = float(yield_record.get('yield_amount', 0))
            
            if crop_type not in crop_stats:
                crop_stats[crop_type] = {'total': 0, 'count': 0}
            
            crop_stats[crop_type]['total'] += yield_amount
            crop_stats[crop_type]['count'] += 1
        
        # Calculate averages
        for crop in crop_stats:
            crop_stats[crop]['average'] = crop_stats[crop]['total'] / crop_stats[crop]['count']
        
        return render_template('admin_dashboard.html', 
                             total_fields=total_fields,
                             total_yield_records=total_yield_records,
                             crop_stats=crop_stats,
                             recent_yields=all_yields[:10])
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}')
        return render_template('admin_dashboard.html', 
                             total_fields=0,
                             total_yield_records=0,
                             crop_stats={},
                             recent_yields=[])

# ---------------------------------------
# Field Management Routes
# ---------------------------------------
@app.route('/fields')
@login_required
def fields():
    try:
        if session.get('user_role') == 'admin':
            # Admin can see all fields
            response = fields_table.scan()
        else:
            # Farmers can only see their own fields
            response = fields_table.query(
                IndexName='FarmerIndex',
                KeyConditionExpression='farmer_id = :farmer_id',
                ExpressionAttributeValues={':farmer_id': session['user_id']}
            )
        
        fields_list = response.get('Items', [])
        return render_template('fields.html', fields=fields_list)
    except Exception as e:
        flash(f'Error loading fields: {str(e)}')
        return render_template('fields.html', fields=[])

@app.route('/fields/add', methods=['GET', 'POST'])
@login_required
def add_field():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        field_name = data.get('field_name')
        location = data.get('location')
        area_hectares = data.get('area_hectares')
        soil_type = data.get('soil_type')
        
        if not all([field_name, location, area_hectares, soil_type]):
            flash('All fields are required')
            return render_template('add_field.html') if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        field_id = str(uuid.uuid4())
        
        try:
            fields_table.put_item(Item={
                'field_id': field_id,
                'farmer_id': session['user_id'],
                'field_name': field_name,
                'location': location,
                'area_hectares': Decimal(str(area_hectares)),
                'soil_type': soil_type,
                'created_at': datetime.now().isoformat()
            })
            
            flash('Field added successfully')
            if request.form:
                return redirect(url_for('fields'))
            else:
                return jsonify({'message': 'Field added successfully', 'field_id': field_id}), 201
                
        except Exception as e:
            flash('Failed to add field')
            return render_template('add_field.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('add_field.html')

# ---------------------------------------
# Yield Data Routes
# ---------------------------------------
@app.route('/yield-data')
@login_required
def yield_data():
    try:
        if session.get('user_role') == 'admin':
            # Admin can see all yield data
            response = yield_data_table.scan(Limit=50)
            yields = response.get('Items', [])
        else:
            # Farmers can see yield data for their fields only
            # First get farmer's fields
            fields_response = fields_table.query(
                IndexName='FarmerIndex',
                KeyConditionExpression='farmer_id = :farmer_id',
                ExpressionAttributeValues={':farmer_id': session['user_id']}
            )
            farmer_fields = fields_response.get('Items', [])
            
            yields = []
            for field in farmer_fields:
                yield_response = yield_data_table.query(
                    IndexName='FieldIndex',
                    KeyConditionExpression='field_id = :field_id',
                    ExpressionAttributeValues={':field_id': field['field_id']},
                    ScanIndexForward=False
                )
                field_yields = yield_response.get('Items', [])
                yields.extend(field_yields)
        
        # Sort by harvest date
        yields.sort(key=lambda x: x.get('harvest_date', ''), reverse=True)
        
        return render_template('yield_data.html', yields=yields)
    except Exception as e:
        flash(f'Error loading yield data: {str(e)}')
        return render_template('yield_data.html', yields=[])

@app.route('/yield-data/add', methods=['GET', 'POST'])
@login_required
def add_yield_data():
    if request.method == 'POST':
        try:
            data = request.form if request.form else request.get_json()

            field_id = data.get('field_id')
            crop_type = data.get('crop_type')
            harvest_date = data.get('harvest_date')
            yield_amount = data.get('yield_amount')
            quality_grade = data.get('quality_grade', 'A')

            if not all([field_id, crop_type, harvest_date, yield_amount]):
                flash('All required fields must be filled')
                return render_template('add_yield_data.html') if request.form else jsonify({'error': 'Missing required fields'}), 400

            # Verify field belongs to farmer (if not admin)
            if session.get('user_role') != 'admin':
                field_response = fields_table.get_item(Key={'field_id': field_id})
                field = field_response.get('Item')
                if not field or field.get('farmer_id') != session['user_id']:
                    flash('Invalid field selection')
                    return render_template('add_yield_data.html') if request.form else jsonify({'error': 'Invalid field'}), 400

            yield_id = str(uuid.uuid4())
            yield_amount_decimal = Decimal(str(yield_amount))

            # Check for yield anomalies
            historical_response = yield_data_table.query(
                IndexName='FieldIndex',
                KeyConditionExpression='field_id = :field_id',
                ExpressionAttributeValues={':field_id': field_id}
            )
            historical_yields = historical_response.get('Items', [])
            
            if historical_yields:
                avg_yield = sum(float(y.get('yield_amount', 0)) for y in historical_yields) / len(historical_yields)
                is_anomaly, percentage_diff = analyze_yield_anomaly(float(yield_amount), avg_yield)
                
                if is_anomaly:
                    alert_message = f"Yield Anomaly Detected!\nField ID: {field_id}\nCrop: {crop_type}\nCurrent Yield: {yield_amount}\nHistorical Avg: {avg_yield:.2f}\nDifference: {percentage_diff:.1f}%"
                    send_sns_alert(alert_message, "Crop Yield Anomaly Alert")

            # Save yield data
            yield_data_table.put_item(Item={
                'yield_id': yield_id,
                'field_id': field_id,
                'farmer_id': session['user_id'],
                'crop_type': crop_type,
                'harvest_date': harvest_date,
                'yield_amount': yield_amount_decimal,
                'quality_grade': quality_grade,
                'created_at': datetime.now().isoformat()
            })

            flash('Yield data added successfully')
            if request.form:
                return redirect(url_for('yield_data'))
            else:
                return jsonify({'message': 'Yield data added successfully', 'yield_id': yield_id}), 201

        except Exception as e:
            print(f"Error adding yield data: {e}")
            flash('Failed to add yield data')
            return render_template('add_yield_data.html') if request.form else jsonify({'error': str(e)}), 500

    # GET request: fetch farmer's fields for dropdown
    try:
        if session.get('user_role') == 'admin':
            fields_response = fields_table.scan()
        else:
            fields_response = fields_table.query(
                IndexName='FarmerIndex',
                KeyConditionExpression='farmer_id = :farmer_id',
                ExpressionAttributeValues={':farmer_id': session['user_id']}
            )
        
        farmer_fields = fields_response.get('Items', [])
        return render_template('add_yield_data.html', fields=farmer_fields)

    except Exception as e:
        print(f"Error loading fields for yield data form: {e}")
        flash('Error loading form')
        return redirect(url_for('yield_data'))

# ---------------------------------------
# Weather Data Routes
# ---------------------------------------
@app.route('/weather', methods=['GET', 'POST'])
@login_required
def weather():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        location = data.get('location')
        date = data.get('date')
        temperature_max = data.get('temperature_max')
        temperature_min = data.get('temperature_min')
        rainfall = data.get('rainfall', 0)
        humidity = data.get('humidity')
        
        if not all([location, date, temperature_max, temperature_min, humidity]):
            flash('All required fields must be filled')
            return render_template('weather.html') if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        weather_id = str(uuid.uuid4())
        
        try:
            weather_table.put_item(Item={
                'weather_id': weather_id,
                'location': location,
                'date': date,
                'temperature_max': Decimal(str(temperature_max)),
                'temperature_min': Decimal(str(temperature_min)),
                'rainfall': Decimal(str(rainfall)),
                'humidity': Decimal(str(humidity)),
                'recorded_by': session['user_id'],
                'created_at': datetime.now().isoformat()
            })
            
            flash('Weather data added successfully')
            if request.form:
                return redirect(url_for('weather'))
            else:
                return jsonify({'message': 'Weather data added successfully', 'weather_id': weather_id}), 201
                
        except Exception as e:
            flash('Failed to add weather data')
            return render_template('weather.html') if request.form else jsonify({'error': str(e)}), 500
    
    # GET request: show weather data
    try:
        response = weather_table.scan(Limit=20)
        weather_data = response.get('Items', [])
        weather_data.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        return render_template('weather.html', weather_data=weather_data)
    except Exception as e:
        flash(f'Error loading weather data: {str(e)}')
        return render_template('weather.html', weather_data=[])

# ---------------------------------------
# API Routes
# ---------------------------------------
@app.route('/api/yield-stats')
@admin_required
def api_yield_stats():
    try:
        response = yield_data_table.scan()
        yields = response.get('Items', [])
        
        # Calculate statistics by crop type
        crop_stats = {}
        for yield_record in yields:
            crop_type = yield_record.get('crop_type', 'Unknown')
            yield_amount = float(yield_record.get('yield_amount', 0))
            
            if crop_type not in crop_stats:
                crop_stats[crop_type] = []
            
            crop_stats[crop_type].append(yield_amount)
        
        # Calculate averages and totals
        stats = {}
        for crop, amounts in crop_stats.items():
            stats[crop] = {
                'total_records': len(amounts),
                'average_yield': sum(amounts) / len(amounts) if amounts else 0,
                'total_yield': sum(amounts)
            }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-yields')
@login_required
def api_recent_yields():
    try:
        if session.get('user_role') == 'admin':
            response = yield_data_table.scan(Limit=10)
        else:
            # Get farmer's fields first
            fields_response = fields_table.query(
                IndexName='FarmerIndex',
                KeyConditionExpression='farmer_id = :farmer_id',
                ExpressionAttributeValues={':farmer_id': session['user_id']}
            )
            farmer_fields = fields_response.get('Items', [])
            
            yields = []
            for field in farmer_fields:
                yield_response = yield_data_table.query(
                    IndexName='FieldIndex',
                    KeyConditionExpression='field_id = :field_id',
                    ExpressionAttributeValues={':field_id': field['field_id']},
                    Limit=5,
                    ScanIndexForward=False
                )
                field_yields = yield_response.get('Items', [])
                yields.extend(field_yields)
            
            # Sort and limit
            yields.sort(key=lambda x: x.get('harvest_date', ''), reverse=True)
            return jsonify(yields[:10])
        
        yields = response.get('Items', [])
        yields.sort(key=lambda x: x.get('harvest_date', ''), reverse=True)
        
        return jsonify(yields)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# ---------------------------------------
# Main
# ---------------------------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
