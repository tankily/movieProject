# coding:utf8

from . import home
from sqlalchemy import or_
from flask import render_template, redirect, url_for, flash, session, request
from app.home.forms import RegisterForm, LoginForm, UserDetailForm, PwdForm, CommentForm
from app.models import User, Userlog, Comment, Movie, Moviecol, Preview, Tag
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import uuid, os, stat, datetime
from app import db, app
from functools import wraps


def user_login_req(f):
    """定义装饰器添加访问权限"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def change_filename(filename):
    """对文件名称进行散列化"""
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


# @home.route("/")
# def home():
#     return redirect(url_for('home.index', page=1))


@home.route("/<int:page>/", methods=['GET'])
def index(page=None):
    tags = Tag.query.all()
    tid = int(request.args.get('tid', 0))
    star = int(request.args.get('star', 0))
    time = int(request.args.get('time', 0))
    play_num = int(request.args.get('pn', 0))
    comment_num = int(request.args.get('cn', 0))
    page_data = Movie.query
    if tid != 0:
        page_data = page_data.filter_by(tag_id=tid)
    if star != 0:
        page_data = page_data.filter_by(star=star)
    if time != 0:
        if time == 1:
            page_data = page_data.order_by(
                db.desc(Movie.release_time)
            )
        else:
            page_data = page_data.order_by(
                db.asc(Movie.release_time)
            )
    if play_num != 0:
        if play_num == 1:
            page_data = page_data.order_by(
                db.desc(Movie.playnum)
            )
        else:
            page_data = page_data.order_by(
                db.asc(Movie.playnum)
            )

    if comment_num != 0:
        if comment_num == 1:
            page_data = page_data.order_by(
                db.desc(Movie.commentnum)
            )
        else:
            page_data = page_data.order_by(
                db.asc(Movie.commentnum)
            )
    if page is None:
        page = 1
    page_data = page_data.paginate(page=page, per_page=10)
    p = dict(
        tid=tid,
        star=star,
        time=time,
        pn=play_num,
        cn=comment_num
    )
    return render_template("home/index.html", tags=tags, p=p, page_data=page_data)


@home.route("/login/", methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('home.index', page=1))
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter(
            or_(User.name == data['account'], User.email == data['account'], User.phone == data['account'])).first()
        if not user.check_pwd(data["pwd"]):
            flash("密码错误！", 'err')
            return redirect(url_for("home.login"))
        session['user'] = data["account"]
        session['user_id'] = user.id
        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for('home.index', page=1))
    return render_template("home/login.html", form=form)


@home.route("/logout/")
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for("home.login"))  # 跳转到home模块下的login路由


@home.route("/register/", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash('注册成功！', 'ok')

    return render_template("home/register.html", form=form)


@home.route("/user/", methods=['GET', 'POST'])
@user_login_req
def user():
    form = UserDetailForm()
    user = User.query.get(session['user_id'])
    if request.method == 'GET':
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        if form.face.data != '':
            file_face = secure_filename(form.face.data.filename)
            if not os.path.exists(app.config['UP_DIR'] + 'users/'):
                os.makedirs(app.config['UP_DIR'] + 'users/')
                os.chmod(app.config['UP_DIR'] + 'users/', stat.S_IRWXU)
            user.face = change_filename(file_face)
            form.face.data.save(app.config['UP_DIR'] + 'users/' + user.face)

        name_count = User.query.filter_by(name=data['name']).count()
        if data['name'] != user.name and name_count >= 1:
            flash('昵称已经存在！', 'err')
            return redirect(url_for('home.user'))

        email_count = User.query.filter_by(email=data['email']).count()
        if data['email'] != user.email and email_count >= 1:
            flash('邮箱已经存在！', 'err')
            return redirect(url_for('home.user'))

        phone_count = User.query.filter_by(name=data['phone']).count()
        if data['phone'] != user.phone and phone_count >= 1:
            flash('手机号已经存在！', 'err')
            return redirect(url_for('home.user'))

        user.name = data['name']
        user.email = data['email']
        user.phone = data['phone']
        user.info = data['info']
        db.session.add(user)
        db.session.commit()
        flash('修改成功', 'ok')
        return redirect(url_for('home.user'))
    return render_template("home/user.html", form=form, user=user)


@home.route("/pwd/", methods=['GET', 'POST'])
@user_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=session['user']).first()
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash('修改密码成功, 请重新登录', 'ok')
        return redirect(url_for('home.logout'))
    return render_template("home/pwd.html", form=form)


@home.route("/comment/<int:page>/", methods=['GET'])
@user_login_req
def comment(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        session['user_id'] == Comment.user_id
    ).order_by(
        db.desc(Comment.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("home/comment.html", page_data=page_data)


@home.route("/loginlog/<int:page>/", methods=['GET'])
@user_login_req
def loginlog(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.filter_by(user_id=session['user_id']) \
        .order_by(db.desc(Userlog.addtime)).paginate(page=page, per_page=10)
    return render_template("home/loginlog.html", page_data=page_data)


@home.route("/moviecol/<int:page>/", methods=['GET'])
@user_login_req
def moviecol(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.filter_by(user_id=session['user_id']) \
        .join(Movie).filter(Moviecol.movie_id == Movie.id) \
        .order_by(db.desc(Moviecol.addtime)).paginate(page=page, per_page=10)
    return render_template("home/moviecol.html", page_data=page_data)


@home.route("/animation/")
def animation():
    data = Preview.query.all()
    return render_template("home/animation.html", data=data)


@home.route("/search/<int:page>/", methods=['GET'])
def search(page=None):
    if page is None:
        page = 1
    key = request.args.get('key', '')
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).order_by(
        db.desc(Movie.addtime)
    ).paginate(page=page, per_page=10)
    page_data.key = key
    count = Movie.query.filter(Movie.title.ilike('%' + key + '%')).count()
    return render_template("home/search.html", key=key, page_data=page_data, count=count)


@home.route("/play/<int:id>/<int:page>/", methods=['GET', 'POST'])
def play(id=None, page=None):
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == id
    ).first_or_404()
    movie.playnum = movie.playnum + 1
    form = CommentForm()
    if page is None:
        page = 1
    page_data = Comment.query.filter_by(movie_id=id).join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        db.desc(Comment.addtime)
    ).paginate(page=page, per_page=10)

    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['input_content'],
            movie_id=movie.id,
            user_id=session['user_id']
        )
        movie.commentnum = movie.commentnum + 1
        db.session.add(comment)
        db.session.add(movie)
        db.session.commit()
        return redirect(url_for('home.play', id=id, page=1))
    db.session.add(movie)
    db.session.commit()
    return render_template("home/play.html", movie=movie, form=form, page_data=page_data)


@home.route('/moviecol/add/', methods=['GET'])
def moviecol_add():
    mid = request.args.get('mid', '')
    moviecol_count = Moviecol.query.filter_by(user_id=session['user_id'], movie_id=int(mid)).count()
    if moviecol_count >= 1:
        state = dict(ok=0)
    else:
        state = dict(ok=1)
        moviecol = Moviecol(
            movie_id=int(mid),
            user_id=session['user_id']
        )
        db.session.add(moviecol)
        db.session.commit()
    import json
    return json.dumps(state)

