from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
import os
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from http import HTTPStatus
import jwt
from werkzeug.exceptions import BadRequest
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'recipe_database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.Text(), nullable=False)
    access_token = db.Column(db.Text(), nullable=True)

    def __repr__(self):
        return f"<User {self.id} {self.email}>"


class Recipe(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100))
    ingredients = db.Column(db.Text)
    instructions = db.Column(db.Text)
    serving_size = db.Column(db.Float)
    category = db.Column(db.String(50))
    notes = db.Column(db.Text)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

    def __str__(self):
        return f'{self.name}, {self.created_on}'


class RecipeSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Recipe
        include_relationships = True
        load_instance = True
        include_fk = True


@app.route('/get_all_recipes/')
def get_all_recipes():
    if 'Authorization' in request.headers:
        token = request.headers['Authorization']
        user = User.query.filter_by(access_token=token).first()
        if user:
            recipes = Recipe.query.filter_by(user=user.id)
            ser = RecipeSchema()
            data = ser.dump(recipes, many=True)
            return jsonify(data)

        else:
            raise BadRequest("Invalid Token")
    else:
        raise BadRequest("Authorization were not provided")


@app.route('/create-recipe/', methods=['POST'])
def create_recipe():
    if request.method == 'POST':
        print(request.headers)
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
            
            user = User.query.filter_by(access_token=token).first()
            if user:
                request_data = request.get_json()
                request_data.update({"user": int(user.id)})
                session = db.session()
                schema = RecipeSchema()
                load_data = schema.load(request_data, session=session)
                session.add(load_data)
                session.commit()
                session.close()
                return jsonify({"result": "created Successfully"})
            else:
                raise BadRequest("Invalid Token")
        else:
            raise BadRequest("Authorization were not provided")

@app.route('/delete-recipe/<id>/')
def delete(id):
    recipe = Recipe.query.get(id)
    if recipe:
        db.session.delete(recipe)
        db.session.commit()
        return jsonify({"result": "Deleted Successfully"})
    else:
        return jsonify({"result": "Not Found"})


@app.route('/signup/', methods=['POST'])
def signup():
    """
        Create a new user account
    """

    data = request.get_json()

    try:

        new_user = User(
            email=data.get('email'),
            password_hash=generate_password_hash(data.get('password'))
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"result": "Signup successfully"})

    except Exception as e:
        print(str(e))
        return jsonify({"result": "Email Already exists"})


@app.route('/signin/', methods=['POST'])
def signin():
    """
        Generate a JWT
    """

    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if (user is not None) and check_password_hash(user.password_hash, password):

        access_token = jwt.encode({"email": user.email}, "secret", algorithm="HS256")

        response = {
            'acccess_token': access_token,
        }
        user.access_token = access_token
        # db.session()
        db.session.commit()
        return response, HTTPStatus.OK

    raise BadRequest("Invalid Username or password")


if __name__ == "__main__":
    app.run(debug=True)  # Run flask app.
