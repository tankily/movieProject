# coding:utf8
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import os
import pymysql

app = Flask(__name__)  # type: Flask
app.debug = True
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:123456@127.0.0.1:3306/movie"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SECRET_KEY"] = 'c23f9075dbf0498ab87ad21c620a9601'  # 创建表单时要用
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/")  # 创建上传目录

db = SQLAlchemy(app)  # type: SQLAlchemy

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("home/404.html"), 404




