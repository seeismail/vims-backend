from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import uuid
import jwt
import datetime
from datetime import date, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:fyp-backend@localhost/db_vims'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'fyp'

db = SQLAlchemy(app)

########################### Auth ###################################

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String, unique=True)
    name = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True,nullable=False)
    password = db.Column(db.String, nullable=False)
    admin= db.Column(db.Boolean, nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'token-required' in request.headers:
            token = request.headers['token-required']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'],"HS256")
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

   
@app.route('/auth/decode_token', methods=['GET'])
@token_required
def decode(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    token=None

    if 'token-required' in request.headers:
            token = request.headers['token-required']

    print(token)
    if not token:
            return jsonify({'message' : 'Token is missing!'}), 401     

    try: 
        data = jwt.decode(token, app.config['SECRET_KEY'],"HS256")
        current_user = User.query.filter_by(public_id=data['public_id']).first()
        user_data = {}
        user_data['public_id'] = current_user.public_id
        user_data['name'] = current_user.name
        user_data['email'] = current_user.email
        user_data['password'] =current_user.password
        user_data['admin'] = current_user.admin
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401           


    return jsonify(user_data)


@app.route('/auth/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()
    
    hashed_password = generate_password_hash(data['password'], method='sha256')

    if bool(User.query.filter_by(email=data['email']).first()):
        return jsonify({'message' : "User Email Already Exists"})

    if bool(User.query.filter_by(name=data['name']).first()):
        return jsonify({'message' : "User Name Already Exists"})

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'],password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify(output)

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify(user_data)

@app.route('/users/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/users', methods=['GET'])
def user_search():
    temp=request.args.get('data')
    output=[]
    if not temp:
        return jsonify({'Message':'Invalid Argument'})
    try:
        X=int(temp)
        print(X)
        Users = User.query.filter(User.id==X)
        for user in Users:
            user_data={}
            user_data['id']=user.id
            user_data['name']=user.name
            user_data['email']=user.email
            user_data['public_id']=user.public_id
            output.append(user_data) 
        assert len(output)>0


    except:
        X=str(temp)
        print(X)
        Users = User.query.filter(User.name.ilike(X)|(User.email.ilike(X))|(User.public_id.ilike(X)))
        for user in Users:
            user_data={}
            user_data['id']=user.id
            user_data['name']=user.name
            user_data['email']=user.email
            user_data['public_id']=user.public_id
            output.append(user_data)
        
    return jsonify(output) 
    


@app.route('/users', methods=['PUT'])
@token_required
def update_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    token=None

    if 'token-required' in request.headers:
            token = request.headers['token-required']

    if not token:
            return jsonify({'message' : 'Token is missing!'}), 401       

    try: 
        decoded_data = jwt.decode(token, app.config['SECRET_KEY'],"HS256")
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401           

    user = User.query.filter_by(public_id=decoded_data['public_id']).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    data = request.get_json()

    user.name = data['name']
    user.password = generate_password_hash(data['password'], method='sha256')
    if bool(User.query.filter_by(email=data['email']).first()):
        return jsonify({'message' : "User Already Exists"})
    user.email=data['email']
    db.session.commit()

    return jsonify({'message' : 'User Updated!'})



@app.route('/users/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/auth/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'])
        print(token)
        return jsonify(token)

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})



########################### Auth END ###################################

class Vehicle(db.Model):
    __tablename__ = "vehicles"

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    num_plate = db.Column(db.String(7), nullable=False, unique=True)
    type = db.Column(db.String)
    suspicious = db.Column(db.Boolean, nullable=False, default=False)
    registered=db.relationship('Registered', backref='vehicles', cascade="all,delete")

class Registered(db.Model):
    """
    Registered User
    """

    __tablename__ = "registered"

    regid = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    cnic = db.Column(db.String, nullable=False)
    contactno = db.Column(db.String, nullable=False)
    gender = db.Column(db.String, nullable=False)
    dor = db.Column(db.DateTime, nullable=False)
    doe = db.Column(db.DateTime, nullable=False)
    vehicle_id = db.Column(
        db.Integer, db.ForeignKey("vehicles.id"), unique=True, nullable=False
    )

class Visitor(db.Model):
    __tablename__ = "visitors"

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    cnic = db.Column(db.String, nullable=False)
    license_plate = db.Column(db.String, nullable=False) # license


class CarLogs(db.Model):
    __tablename__ = "carlogs"

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    image_path = db.Column(db.String, nullable=False)
    is_registered = db.Column(db.Boolean, default=False)
    is_suspicious = db.Column(db.Boolean, default=False)
    time = db.Column(db.DateTime, nullable=False)
    vehicle_id = db.Column(
        db.Integer, db.ForeignKey("vehicles.id"), unique=False, nullable=True
    )
########## DashBoard APIs ##############


########################## Bar Chart API #############################
@app.route("/barVehicles", methods=["GET"])
def bar_vehicles():
    cars = Vehicle.query.filter_by(type="car").all()
    buses = Vehicle.query.filter_by(type="bus").all()
    bikes = Vehicle.query.filter_by(type="bike").all()

    return {"car": len(cars), "buses": len(buses),"bike": len(bikes)}   

########################## Pie Chart API #############################
@app.route("/pieVehicles", methods=["GET"])
def pie_vehciles():
    cars = Vehicle.query.filter_by(type="car", suspicious=False).all()
    buses = Vehicle.query.filter_by(type="bus", suspicious=False).all()
    bikes = Vehicle.query.filter_by(type="bike", suspicious=False).all()

    sus_cars = Vehicle.query.filter_by(type="car", suspicious=True).all()
    sus_buses = Vehicle.query.filter_by(type="bus", suspicious=True).all()
    sus_bikes = Vehicle.query.filter_by(type="bike", suspicious=True).all()

    return {
        "car": len(cars) + len(sus_cars),
        "buses": len(buses) + len(sus_buses),
        "bikes": len(bikes) + len(sus_bikes),
        "sus_cars": len(sus_cars),
        "sus_buses": len(sus_buses),
        "sus_bikes": len(sus_bikes),
        # reg green blue colors list
        "colors": ["#00FF00", "#0000FF", "#FF0000"],
    }

########################## line Chart API #############################
def daterange(start_date, end_date):
    start_date = date(*map(lambda a: int(a), start_date.split("-")))
    end_date = date(*map(lambda a: int(a), end_date.split("-")))

    for n in range(int((end_date - start_date).days)):
        yield start_date + timedelta(n)


@app.route("/carCounts/<starting_date>/<ending_date>", methods=["GET"])
def car_count_datediff(starting_date: str, ending_date: str):
    list_dates = []
    car_counts = []
    for curr_date in daterange(starting_date, ending_date):
        date_formatted = curr_date.strftime("%Y-%m-%d")
        list_dates.append(date_formatted)
        # CarLogs.query.filter(CarLogs.time = f'{date_formatted}').count()
        count = CarLogs.query.filter(CarLogs.time >= "{}".format(curr_date)).count()
        car_counts.append(count)

    return {"list_dates": list_dates, "car_counts": car_counts}



######################################### END DASHBOARD APIs ####################################     

# Create a Vehicle
@app.route('/vehicles', methods=['POST'])
def add_vehicle():

    data = request.get_json()
    
    new_vehicle = Vehicle(num_plate=data['num_plate'], type=data['type'], suspicious=False)
    db.session.add(new_vehicle)
    db.session.commit()

    return jsonify({'Message' : 'Vehcile Added!'})

#All Vehicles
@app.route('/vehicles', methods=['GET'])
def get_all_vehicle():
    vehicles = Vehicle.query.all()
    output = []
    for vehicle in vehicles:
        user_data = {}
        user_data['id'] = vehicle.id
        user_data['num_plate'] = vehicle.num_plate
        user_data['type'] = vehicle.type
        user_data['suspicious'] = vehicle.suspicious
        output.append(user_data)

    return jsonify(output)

#Delete Vehicle by Number Plate
@app.route('/delete_vehicle/<num_plate>', methods=['DELETE'])
def delete_vehicle(num_plate):
    reg_vehicle = Vehicle.query.filter_by(num_plate=num_plate).first()

    if not reg_vehicle:
        return jsonify({'message' : 'Visitor Not Found...!'})

    db.session.delete(reg_vehicle)
    db.session.commit()

    return jsonify({'message' : 'The Registered Vehicle has been deleted!'})


# Mark Vehicle Suspicious
@app.route('/suspicious_vehicle/<number_plate>', methods=['PUT'])
def suspiciousVehcile(number_plate):

    vehicle = Vehicle.query.filter_by(num_plate=number_plate).first()

    if not vehicle:
        return jsonify({'message' : 'No Vehicle found!'})

    vehicle.suspicious = True
    db.session.commit()

    return jsonify({'message' : 'Vehicle added to suspicious category...'})

# Registration of Individual along with his Vehicle
@app.route('/registration', methods=['POST'])
def registration_visitor():
    data = request.get_json()

    new_reg = Registered(name=data['name'], cnic=data['cnic'], contactno=data['contactno'], gender=data['gender'], dor=data['dor'], doe=data['doe'], vehicles=Vehicle(num_plate=data['num_plate'],type=data['type']))

    db.session.add(new_reg)
    db.session.commit()

    return jsonify({'Message' : 'Sucessfully Added!'})

# Update Registered Visitor
@app.route('/update_visitor/<regid>', methods=['PATCH'])
def update_reg_visitor(regid):
    
    data = request.get_json()
    print(regid)
    reg_visitor=Registered.query.filter_by(regid=regid).first()

    if reg_visitor is None:
         return jsonify({'message' : 'Doesnot Exist!'})

    try:
        reg_visitor.name =data['name']
        reg_visitor.cnic =data['cnic'] 
        reg_visitor.contactno =data['contactno'] 
        reg_visitor.gender =data['gender'] 
        reg_visitor.dor =data['dor'] 
        reg_visitor.doe =data['doe'] 
        reg_visitor.vehicle_id =data['vehicel_id']
    finally:
        db.session.commit()
        return jsonify({'message' : 'User Updated!'})

    

    

# Delete Registered Visitor
@app.route('/delete_visitor/<regid>', methods=['DELETE'])
def delete_visitor(regid):
    reg_visitor = Registered.query.filter_by(regid=regid).first()

    if not reg_visitor:
        return jsonify({'message' : 'Visitor Not Found...!'})

    db.session.delete(reg_visitor)
    db.session.commit()

    return jsonify({'message' : 'The Registered Visitor has been deleted!'})


@app.route('/registered_visitors', methods=['GET'])
def registered_visitors_search():
    temp=request.args.get('data')
    output=[]
    if not temp:
        return jsonify({'Message':'Invalid Argument'})
    try:
        X=int(temp)
        print(X)
        regVisitors = Registered.query.filter(Registered.regid==X)
        for regVisitor in regVisitors:
            user_data={}
            user_data['regid']=regVisitor.regid
            user_data['name']=regVisitor.name
            user_data['cnic']=regVisitor.cnic
            user_data['contactno']=regVisitor.contactno
            user_data['gender']=regVisitor.gender
            user_data['dor'] = regVisitor.dor
            user_data['doe'] = regVisitor.doe
            user_data['vehicel_id']=regVisitor.vehicle_id
            output.append(user_data) 
        assert len(output)>0


    except:
        X=str(temp)
        print(X)
        regVisitors = Registered.query.filter(Registered.name.ilike(X)|(Registered.cnic.ilike(X))|(Registered.contactno.ilike(X)))
        for regVisitor in regVisitors:
            user_data={}
            user_data['regid']=regVisitor.regid
            user_data['name']=regVisitor.name
            user_data['cnic']=regVisitor.cnic
            user_data['contactno']=regVisitor.contactno
            user_data['gender']=regVisitor.gender
            user_data['vehicel_id']=regVisitor.vehicle_id
            output.append(user_data)
        
    return jsonify(output) 
    
#add Guest Visitor
@app.route('/guest_visitors', methods=['POST'])
def add_guest_visitor():
    data = request.get_json()

    guest_reg = Visitor(name=data['name'], cnic=data['cnic'],license_plate=data['license_plate'])

    db.session.add(guest_reg)
    db.session.commit()

    return jsonify({'Message' : 'Sucessfully Added!'})

#get guest visitor by url query
@app.route('/search_guest_visitors', methods=['GET'])
def guestSearch():
    temp=request.args.get('search')
    output=[]
    if not temp:
        return jsonify({'Message':'Invalid Argument'})
    
    try:
        X=int(temp)
        print(X)
        gueVisitors = Visitor.query.filter(Visitor.id==X)
        for gueVisitor in gueVisitors:
            user_data={}
            user_data['id']=gueVisitor.id
            user_data['name']=gueVisitor.name
            user_data['cnic']=gueVisitor.cnic
            user_data['license_plate']=gueVisitor.license_plate
            output.append(user_data) 
        assert len(output)>0


    except:
        X=str(temp)
        print(X)
        gueVisitors = Visitor.query.filter(Visitor.name.ilike(X)|(Visitor.cnic.ilike(X))|(Visitor.license_plate.ilike(X)))
        for gueVisitor in gueVisitors:
            user_data={}
            user_data['id']=gueVisitor.id
            user_data['name']=gueVisitor.name
            user_data['cnic']=gueVisitor.cnic
            user_data['license_plate']=gueVisitor.license_plate
            output.append(user_data)
        
    return jsonify(output)

# Delete Registered Visitor
@app.route('/delete_guest_visitor/<id>', methods=['DELETE'])
def delete_guest_visitor(id):
    gue_visitor = Visitor.query.filter_by(id=id).first()

    if not gue_visitor:
        return jsonify({'message' : 'Visitor Not Found...!'})

    db.session.delete(gue_visitor)
    db.session.commit()

    return jsonify({'message' : 'The Guest Visitor has been deleted!'})    
    
         

if __name__ == '__main__':
    db.create_all()
    db.session.commit()
    app.run()





