# coding:utf8

from . import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, Userlog, Auth, Role
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename  # 转化为安全的文件名称
import os, stat, uuid, datetime


# 上下文应用处理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    return data


def admin_login_req(f):
    """定义装饰器添加访问权限"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def admin_auth(f):
    """权限控制装饰器"""

    @wraps(f)
    def decroated_function(*args, **kwargs):
        admin = Admin.query.join(Role).filter(
            Role.id == Admin.role_id,
            Admin.id == session['admin_id']
        ).first()
        if admin.is_super != 0:
            auths = admin.role.auths
            auths = [int(v) for v in auths.split(',')]
            auth_list = Auth.query.all()
            urls = [v.url for v in auth_list for val in auths if val == v.id]
            rule = str(request.url_rule)
            if rule not in urls:
                abort(404)
        return f(*args, **kwargs)

    return decroated_function


def change_filename(filename):
    """对文件名称进行散列化"""
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route("/")
@admin_login_req
@admin_auth
def index():
    return render_template("admin/index.html")


@admin.route("/login/", methods=['GET', 'POST'])
def login():
    if 'admin' in session:
        return redirect(url_for('admin.index'))
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data["pwd"]):
            flash("密码错误！", 'err')
            return redirect(url_for("admin.login"))
        session['admin'] = data["account"]
        session['admin_id'] = admin.id
        adminlog = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template("admin/login.html", form=form)


@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin", None)
    session.pop('admin_id', None)
    return redirect(url_for("admin.login"))


@admin.route("/pwd/", methods=['GET', 'POST'])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session['admin']).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功, 请重新登录', 'ok')
        return redirect(url_for('admin.logout'))
    return render_template("admin/pwd.html", form=form)


@admin.route("/tag/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tagrow = Tag.query.filter_by(name=data['name']).count()
        if tagrow == 1:
            flash('标签名已存在', 'err')
            return redirect(url_for('admin.tag_add'))
        tag = Tag(
            name=data['name']
        )
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason='添加一个标签：%s' % data['name']
        )
        db.session.add(tag)
        db.session.add(oplog)
        db.session.commit()
        flash('添加标签成功', 'ok')
        return redirect(url_for('admin.tag_add'))
    return render_template("admin/tag_add.html", form=form)


@admin.route("/tag/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_row = Tag.query.filter_by(name=data['name']).count()
        if tag.name != data['name'] and tag_row == 1:
            flash('标签名已存在', 'err')
            return redirect(url_for('admin.tag_edit', id=id))
        tag.name = data['name']
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='修改标签：%s' % data['name'],
            ip=request.remote_addr
        )
        db.session.add(tag)
        db.session.add(oplog)
        db.session.commit()
        flash('修改标签成功', 'ok')
        return redirect(url_for('admin.tag_edit', id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


@admin.route("/tag/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/tag_list.html", page_data=page_data)


@admin.route("/tag/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    oplog = Oplog(
        admin_id=session['admin_id'],
        reason='删除标签：%s' % tag.name,
        ip=request.remote_addr
    )
    db.session.delete(tag)
    db.session.add(oplog)
    db.session.commit()
    flash("删除标签成功！", "ok")
    return redirect(url_for('admin.tag_list', page=1))


@admin.route("/movie/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        movie_count = Tag.query.filter_by(name=data['title']).count()
        if movie_count >= 1:
            flash('片名已存在', 'err')
            return redirect(url_for('admin.movie_add'))
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])  # 创建目录
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)  # 授权可读写
        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config['UP_DIR'] + url)
        form.url.data.save(app.config['UP_DIR'] + logo)
        movie = Movie(
            title=data['title'],
            url=url,
            info=data['info'],
            logo=logo,
            star=int(data['star']),
            playnum=0,
            commentnum=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            release_time=data['release_time'],
            length=data['length']
        )
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='添加电影：%s' % data['title'],
            ip=request.remote_addr
        )
        db.session.add(movie)
        db.session.add(oplog)
        db.session.commit()
        flash('添加电影成功', 'ok')
        return redirect(url_for('admin.movie_add'))
    return render_template("admin/movie_add.html", form=form)


@admin.route("/movie/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/movie_list.html", page_data=page_data)


@admin.route("/movie/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def movie_del(id=None):
    movie = Movie.query.get_or_404(id)
    movie_file = app.config['UP_DIR'] + movie.url
    logo_file = app.config['UP_DIR'] + movie.logo
    if os.path.isfile(movie_file) and os.path.isfile(logo_file):
        os.remove(movie_file)
        os.remove(logo_file)
    oplog = Oplog(
        admin_id=session['admin_id'],
        reason='删除电影：%s' % movie.title,
        ip=request.remote_addr
    )
    db.session.delete(movie)
    db.session.add(oplog)
    db.session.commit()
    flash('删除电影成功！', 'ok')
    return redirect(url_for('admin.movie_list', page=1))


@admin.route("/movie/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def movie_edit(id=None):
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(id)
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count >= 1 and movie.title != data['title']:
            flash('修改电影失败，片名重复', 'err')
            return redirect(url_for('admin.movie_edit', id=movie.id))
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])  # 创建目录
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)  # 授权可读写

        if form.url.data != '':
            file_url = app.config['UP_DIR'] + movie.url
            if os.path.isfile(file_url):
                os.remove(file_url)

            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + movie.url)

        if form.logo.data != '':
            file_logo = app.config['UP_DIR'] + movie.logo
            if os.path.isfile(file_logo):
                os.remove(file_logo)

            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)

        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.info = data['info']
        movie.title = data['title']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='修改电影：%s' % data['title'],
            ip=request.remote_addr
        )
        db.session.add(movie)
        db.session.add(oplog)
        db.session.commit()
        flash('修改电影成功', 'ok')
        return redirect(url_for('admin.movie_edit', id=movie.id))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


@admin.route("/preview/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)
        logo = change_filename(file_logo)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview = Preview(
            title=data['title'],
            logo=logo
        )
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='添加预告：%s' % data['title'],
            ip=request.remote_addr
        )
        db.session.add(preview)
        db.session.add(oplog)
        db.session.commit()
        flash('预告添加成功', 'ok')
        return redirect(url_for('admin.preview_add'))
    return render_template("admin/preview_add.html", form=form)


@admin.route("/preview/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/preview_list.html", page_data=page_data)


@admin.route("/preview/del/<int:id>", methods=['GET'])
@admin_login_req
@admin_auth
def preview_del(id=None):
    preview = Preview.query.get_or_404(id)
    logo_file = app.config['UP_DIR'] + preview.logo
    if os.path.isfile(logo_file):
        os.remove(logo_file)
    oplog = Oplog(
        admin_id=session['admin_id'],
        reason='修改标签：%s' % preview.title,
        ip=request.remote_addr
    )

    db.session.delete(preview)
    db.session.add(oplog)
    db.session.commit()
    flash('删除预告成功', 'ok')
    return redirect(url_for('admin.preview_list', page=1))


@admin.route("/preview/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def preview_edit(id=None):
    form = PreviewForm()
    form.logo.validators = []
    preview = Preview.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        preview_count = Preview.query.filter_by(title=data['title']).count()
        if preview_count >= 1 and preview.title != data['title']:
            flash('修改预告失败，预告标题重复', 'err')
            return redirect(url_for('admin.preview_edit', id=id))
        preview.title = data['title']

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)
        if form.logo.data != '':
            file_logo = app.config['UP_DIR'] + preview.logo
            if os.path.isfile(file_logo):
                os.remove(file_logo)

            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + preview.logo)
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='修改预告：%s' % data['title'],
            ip=request.remote_addr
        )
        db.session.add(preview)
        db.session.add(oplog)
        db.session.commit()
        flash('预告修改成功', 'ok')
        return redirect(url_for('admin.preview_edit', id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


@admin.route("/user/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        db.desc(User.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


@admin.route("/user/view/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def user_view(id=None):
    user = User.query.get_or_404(id)
    return render_template("admin/user_view.html", user=user)


@admin.route("/user/del/<int:id>", methods=['GET'])
@admin_login_req
def user_del(id=None):
    user = User.query.get_or_404(id)
    face_file = app.config['UP_DIR'] + user.face
    if os.path.isfile(face_file):
        os.remove(face_file)
    oplog = Oplog(
        admin_id=session['admin_id'],
        reason='删除会员：%s' % user.name,
        ip=request.remote_addr
    )
    db.session.delete(user)
    db.session.add(oplog)
    db.session.commit()
    flash('删除会员成功', 'ok')
    return redirect(url_for('admin.user_list', page=1))


@admin.route("/comment/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def comment_list(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        db.desc(Comment.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/comment_list.html", page_data=page_data)


@admin.route('/comment/del/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def comment_del(id=None):
    comment = Comment.query.get_or_404(id)
    oplog = Oplog(
        admin_id=session['admin_id'],
        reason='删除评论：%s' % comment.content,
        ip=request.remote_addr
    )
    db.session.delete(comment)
    db.session.add(oplog)
    db.session.commit()
    flash('删除评论成功！', 'ok')
    return redirect(url_for('admin.comment_list', page=1))


@admin.route("/moviecol/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def moviecol_list(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(
        Movie.id == Moviecol.movie_id,
        User.id == Moviecol.user_id
    ).order_by(
        db.desc(Moviecol.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


@admin.route('/moviecol/del/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(id)
    if moviecol is not None:
        moviecol_list = Moviecol.query.join(Movie).join(User).filter(
            Movie.id == Moviecol.movie_id,
            User.id == Moviecol.user_id,
            Moviecol.id == id
        ).first()
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='删除%s收藏：%s' % (moviecol_list.user.name, moviecol_list.movie.title),
            ip=request.remote_addr
        )
        db.session.delete(moviecol)
        db.session.add(oplog)
        db.session.commit()
        flash('删除收藏成功！', 'ok')
    return redirect(url_for('admin.moviecol_list', page=1))


@admin.route("/oplog/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = Oplog.query.join(Admin).filter(Admin.id == Oplog.admin_id).order_by(
        db.desc(Oplog.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/oplog_list.html", page_data=page_data)


@admin.route("/adminloginlog/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Adminlog.query.join(Admin).filter(Admin.id == Adminlog.admin_id).order_by(
        db.desc(Adminlog.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


@admin.route("/userloginlog/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def userloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.join(User).filter(User.id == Userlog.user_id).order_by(
        db.desc(Userlog.addtime)
    ).paginate(page=page, per_page=10)

    return render_template("admin/userloginlog_list.html", page_data=page_data)


@admin.route("/role/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role_count = Role.query.filter_by(name=data['name']).count()
        if role_count >= 1:
            flash('角色已存在', 'err')
            return redirect(url_for('admin.role_add'))
        role = Role(
            name=data['name'],
            auths=','.join([str(v) for v in data['auths']])
        )
        oplog = Oplog(
            admin_id=session["admin_id"],
            reason='添加一个角色：%s' % data['name'],
            ip=request.remote_addr
        )
        db.session.add(role)
        db.session.add(oplog)
        db.session.commit()
        flash('添加角色成功！', 'ok')
        return redirect(url_for('admin.role_add'))
    return render_template("admin/role_add.html", form=form)


@admin.route("/role/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        db.desc(Role.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html", page_data=page_data)


@admin.route('/role/del/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def role_del(id=None):
    role = Role.query.get_or_404(id)
    oplog = Oplog(
        admin_id=session['admin_id'],
        reason='删除一个角色：%s' % role.name,
        ip=request.remote_addr
    )
    db.session.delete(role)
    db.session.add(oplog)
    db.session.commit()
    flash("删除角色成功！", 'ok')
    return redirect(url_for('admin.role_list', page=1))


@admin.route('/role/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == 'GET':
        auths = role.auths
        form.auths.data = [int(v) for v in auths.split(',')]
    if form.validate_on_submit():
        data = form.data
        role_count = Role.query.filter_by(name=data['name']).count()
        if role_count >= 1 and role.name != data['name']:
            flash('角色已存在！', 'err')
            return redirect(url_for('admin.role_edit', id=id))

        role.name = data['name']
        role.auths = ','.join([str(v) for v in data['auths']])
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='修改一个角色：%s' % data['name'],
            ip=request.remote_addr
        )
        db.session.add(role)
        db.session.add(oplog)
        db.session.commit()
        flash('角色修改成功！', 'ok')
        return redirect(url_for('admin.role_edit', id=id))
    return render_template('admin/role_edit.html', form=form, role=role)


@admin.route("/auth/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth_count = Auth.query.filter_by(name=data['name']).count()
        if auth_count >= 1:
            flash('权限已存在！', 'err')
            return redirect(url_for('admin.auth_add'))
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='添加一个权限：%s' % data['name'],
            ip=request.remote_addr
        )
        db.session.add(auth)
        db.session.add(oplog)
        db.session.commit()
        flash('添加权限成功！', 'ok')
        return redirect(url_for('admin.auth_add'))
    return render_template("admin/auth_add.html", form=form)


@admin.route("/auth/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        db.desc(Auth.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


@admin.route('/auth/del/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def auth_del(id=None):
    auth = Auth.query.get_or_404(id)
    if auth is not None:
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='删除权限：%s' % auth.name,
            ip=request.remote_addr
        )
        db.session.delete(auth)
        db.session.add(oplog)
        db.session.commit()
        flash('删除权限成功！', 'ok')
    return redirect(url_for('admin.auth_list', page=1))


@admin.route("/auth/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth_count = Auth.query.filter_by(name=data['name']).count()
        if auth_count >= 1 and auth.name != data['name']:
            flash('权限已存在！', 'err')
            return redirect(url_for('admin.auth_edit', id=id))
        auth.name = data['name']
        auth.url = data['url']
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='修改一个权限：%s' % data['name'],
            ip=request.remote_addr
        )
        db.session.add(auth)
        db.session.add(oplog)
        db.session.commit()
        flash('修改权限成功！', 'ok')
        return redirect(url_for('admin.auth_edit', id=id))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


@admin.route("/admin/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    if form.validate_on_submit():
        data = form.data
        admin_count = Admin.query.filter_by(name=data['account']).count()
        if admin_count >= 1:
            flash('管理员账号已存在！', 'err')
            return redirect(url_for('admin.admin_add'))

        from werkzeug.security import generate_password_hash
        admin = Admin(
            name=data['account'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role_id'],
            is_super=1  # 普通管理员
        )
        oplog = Oplog(
            admin_id=session['admin_id'],
            reason='添加一个管理员：%s' % data['account'],
            ip=request.remote_addr
        )
        db.session.add(admin)
        db.session.add(oplog)
        db.session.commit()
        flash('添加管理员成功', 'ok')
        return redirect(url_for('admin.admin_add'))
    return render_template("admin/admin_add.html", form=form)


@admin.route("/admin/list/<int:page>/", methods=['GET'])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(Role).filter(Role.id == Admin.role_id).order_by(
        db.desc(Admin.addtime)
    ).paginate(page=page, per_page=10)
    return render_template("admin/admin_list.html", page_data=page_data)
