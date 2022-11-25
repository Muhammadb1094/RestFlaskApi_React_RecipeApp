from flask import Flask, request, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
import os
from flask_migrate import Migrate
from flask_restx import Resource, Namespace, fields
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash
from http import HTTPStatus
from flask_jwt_extended import (create_access_token,
                                create_refresh_token, jwt_required, get_jwt_identity)
from werkzeug.exceptions import Conflict, BadRequest

auth_namespace = Namespace('auth', description="a namespace for authentication")

app = Flask(__name__)

with app.app_context():
    # within this block, current_app points to app.
    print(current_app.name)

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

    def __repr__(self):
        return f"<User {self.id} {self.email}>"


class Recipe(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
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


@app.route('/get_all_recipes/')
def get_all_recipes():
    recipes = Recipe.query.all()
    ser = RecipeSchema()
    data = ser.dump(recipes, many=True)
    return jsonify(data)


@app.route('/create-recipe/', methods=['POST'])
def create_():
    if request.method == 'POST':
        request_data = request.get_json()
        session = db.session()
        schema = RecipeSchema()
        load_data = schema.load(request_data, session=session)
        session.add(load_data)
        session.commit()
        session.close()
        return jsonify({"result": "created Successfully"})


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
def post():
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


#     def post(self):
#         """
#             Generate a JWT
#
#         """
#
#         data = request.get_json()
#
#         email = data.get('email')
#         password = data.get('password')
#
#         user = User.query.filter_by(email=email).first()
#
#         if (user is not None) and check_password_hash(user.password_hash, password):
#             access_token = create_access_token(identity=user.username)
#             refresh_token = create_refresh_token(identity=user.username)
#
#             response = {
#                 'acccess_token': access_token,
#                 'refresh_token': refresh_token
#             }
#
#             return response, HTTPStatus.OK
#
#         raise BadRequest("Invalid Username or password")


if __name__ == "__main__":
    app.run(debug=True)  # Run flask app.
