from datetime import datetime
from flask import render_template, flash, redirect, session, url_for, request, g ,abort
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from flask_babel import _, get_locale
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, PostForm, \
    ResetPasswordRequestForm, ResetPasswordForm, CommentForm, NewsForm
from app.models import User, Post ,News, Picture, Comment, Category, Author ,Tag
from app.email import send_password_reset_email
import os



@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
    g.locale = str(get_locale())


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash(_('Your post is now live!'))
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    posts = current_user.followed_posts().paginate(
        page=page, per_page=app.config["POSTS_PER_PAGE"], error_out=False)
    news = News.query.all()
    pictures = Picture.query.all()
    picture_paths = [picture.filename for picture in pictures]
    next_url = url_for(
        'index', page=posts.next_num) if posts.next_num else None
    prev_url = url_for(
        'index', page=posts.prev_num) if posts.prev_num else None
    return render_template('index.html.j2', title=_('Home'), form=form,
                           posts=posts.items, next_url=next_url,
                           prev_url=prev_url,news=news, pictures=pictures, picture_paths=picture_paths)

@app.route('/search', methods=['GET', 'POST'])
def search():
    query = request.args.get('query') 
    if query:
        filtered_news = News.query.filter(News.title.contains(query)).all()
        if filtered_news:
            return render_template('search.html.j2', news=filtered_news)
        else:
            flash('No news matches your search.')
    return redirect(url_for('index'))

@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page=page, per_page=app.config["POSTS_PER_PAGE"], error_out=False)
    next_url = url_for(
        'explore', page=posts.next_num) if posts.next_num else None
    prev_url = url_for(
        'explore', page=posts.prev_num) if posts.prev_num else None
    return render_template('index.html.j2', title=_('Explore'),
                           posts=posts.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash(_('Invalid username or password'))
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html.j2', title=_('Sign In'), form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user!'))
        return redirect(url_for('login'))
    return render_template('register.html.j2', title=_('Register'), form=form)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash(
            _('Check your email for the instructions to reset your password'))
        return redirect(url_for('login'))
    return render_template('reset_password_request.html.j2',
                           title=_('Reset Password'), form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if user is None:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been reset.'))
        return redirect(url_for('login'))
    return render_template('reset_password.html.j2', form=form)


@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = user.followed_posts().paginate(
        page=page, per_page=app.config["POSTS_PER_PAGE"], error_out=False)
    next_url = url_for(
        'index', page=posts.next_num) if posts.next_num else None
    prev_url = url_for(
        'index', page=posts.prev_num) if posts.prev_num else None
    return render_template('user.html.j2', user=user, posts=posts.items,
                           next_url=next_url, prev_url=prev_url)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash(_('Your changes have been saved.'))
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html.j2', title=_('Edit Profile'),
                           form=form)


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(_('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot follow yourself!'))
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash(_('You are following %(username)s!', username=username))
    return redirect(url_for('user', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(_('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot unfollow yourself!'))
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(_('You are not following %(username)s.', username=username))
    return redirect(url_for('user', username=username))

@app.route('/news/<int:news_id>', methods=['GET', 'POST'])
@login_required
def news_detail(news_id):
    news_item = News.query.get_or_404(news_id)
    pictures = news_item.pictures.all()
    tag = Tag.query.get(news_id)
    form = CommentForm()
    if form.validate_on_submit():
        current_user.comment(form.content.data, news_id)
        db.session.commit()
        flash('Your comment has been published.')
    return render_template('news_detail.html.j2', title=('News Detail'), news_item=news_item, form=form , pictures=pictures, tag=tag)

@app.route('/news/<int:news_id>/comment', methods=['POST'])
@login_required
def comment(news_id):
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(content=form.content.data, news_id=news_id , author_id=current_user.id)
        db.session.add(new_comment)
        db.session.commit()
        flash('Your comment has been published.')
        session['last_comment_content'] = form.content.data
        return redirect(url_for('news_detail', news_id=news_id))
    
@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user != comment.author:
        abort(403)
    form = CommentForm()
    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()
        flash('Your comment has been updated.')
        return redirect(url_for('news_detail', news_id=comment.news_id))
    elif request.method == 'GET':
        form.content.data = comment.content
    return render_template('edit_comment.html.j2', title='Edit Comment', form=form)

@app.route('/category/<int:category_id>', methods=['GET'])
@login_required
def category(category_id):
    category = Category.query.get_or_404(category_id)
    news = News.query.filter_by(category=category).all()
    return render_template('category.html.j2', news=news, category=category)

@app.route('/add_news', methods=['GET', 'POST'])
@login_required
def add_news():
    if not (current_user.is_admin or current_user.author):
        abort(403)
    form = NewsForm()
    categories = Category.query.all()
    author_id = current_user.author.id if current_user.author else None
    form.category.choices = [(c.id, c.name) for c in categories]
    if form.validate_on_submit():
        news = News(title=form.title.data, content=form.content.data, category_id=int(form.category.data), author_id=author_id)
        db.session.add(news)
        db.session.commit()
        tags = form.tags.data.split(',')
        for tag in news.tags.all():
            news.tags.remove(tag) 
        for tag_name in tags:
            tag = Tag.query.filter_by(name=tag_name).first()
            if tag is None:  
                tag = Tag(name=tag_name)
                db.session.add(tag)
            news.tags.append(tag)   
        if 'picture' in request.files:
            file = request.files['picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                picture = Picture(filename=filename, news_id=news.id) 
                db.session.add(picture)
                db.session.commit()
        flash('The news has been added.')
        return redirect(url_for('index'))
    return render_template('add_news.html.j2', form=form)

@app.route('/remove_news/<int:news_id>', methods=['POST'])
@login_required
def remove_news(news_id):
    news = News.query.get_or_404(news_id)
    if not (current_user.is_admin or current_user.id == news.author.user_id):
        abort(403)
    news = News.query.get_or_404(news_id)
    db.session.delete(news)
    db.session.commit()
    flash('The news has been removed.')
    return redirect(url_for('index'))

@app.route('/edit_news/<int:news_id>', methods=['GET', 'POST'])
@login_required
def edit_news(news_id):
    news = News.query.get_or_404(news_id)
    if not (current_user.is_admin or current_user.id == news.author.user_id):
        abort(403)
    form = NewsForm()
    categories = Category.query.all()
    tag = Tag.query.all()
    form.category.choices = [(c.id, c.name) for c in categories]
    picture = None  # Add this line to initialize 'picture'
    if form.validate_on_submit():
        news.title = form.title.data
        news.content = form.content.data
        news.category_id = int(form.category.data)
        for tag in news.tags.all():
            news.tags.remove(tag)
        new_tags = form.tags.data.split(',')
        for tag_name in new_tags:
            tag = Tag.query.filter_by(name=tag_name).first()
            if tag is None:  
                tag = Tag(name=tag_name)
                db.session.add(tag)
            news.tags.append(tag)
        if 'picture' in request.files:
            file = request.files['picture']
            if file and allowed_file(file.filename):
                old_picture = Picture.query.filter_by(news_id=news.id).first()
                if old_picture:
                    db.session.delete(old_picture)
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                picture = Picture(filename=filename, news_id=news.id)
                db.session.add(picture)
                db.session.commit()
                flash('The news has been updated.')
                return redirect(url_for('news_detail', news_id=news.id, picture=picture))
    return render_template('edit_news.html.j2', form=form, news_item=news, picture=picture)

def allowed_file(filename):
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_picture', methods=['POST'])
@login_required
def upload_picture():

    if not current_user.is_admin:
        abort(403)
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        picture = Picture(filename=filename)
        db.session.add(picture)
        db.session.commit()
        flash('The picture has been uploaded.')
        return redirect(url_for('index'))

@app.route('/delete_picture/<int:picture_id>', methods=['POST'])
@login_required
def delete_picture(picture_id):
    if not current_user.is_admin:
        abort(403)
    picture = Picture.query.get_or_404(picture_id)
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], picture.filename))
    db.session.delete(picture)
    db.session.commit()
    flash('The picture has been deleted.')
    return redirect(url_for('index'))

@app.route('/change_picture/<int:picture_id>', methods=['POST'])
@login_required
def change_picture(picture_id):
    if not current_user.is_admin:
        abort(403)
    picture = Picture.query.get_or_404(picture_id)
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], picture.filename))  
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        picture.filename = filename  
        db.session.commit()
        flash('The picture has been changed.')
        return redirect(url_for('index'))