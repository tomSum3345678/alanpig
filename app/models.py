
from datetime import datetime, timedelta, timezone
from hashlib import md5
from app import app, db, login
import jwt

from flask_login import UserMixin

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Table


followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='comment_author', lazy='dynamic', cascade="all, delete-orphan")
    is_admin = db.Column(db.Boolean, default=False)
    author = db.relationship('Author', backref='user', uselist=False)
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def __repr__(self) -> str:
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode("utf-8")).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        followed = Post.query.join(
            followers, followers.c.followed_id == Post.user_id
        ).filter(followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode({"reset_password": self.id,
                           "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)},
                          app.config["SECRET_KEY"], algorithm="HS256")

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")[
                "reset_password"]
        except:           
            return None
        return User.query.get(id)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self) -> str:
        return f'<Post {self.body}>'
    
class News(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    title = db.Column(db.String(128), nullable=False, index=True)
    content = db.Column(db.String(1024), nullable=True)
    pictures = db.relationship('Picture', backref='news', lazy='dynamic')  
    comments = db.relationship('Comment', back_populates='news', cascade='all, delete-orphan')
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category', backref='news_items', overlaps="category,news_items")
    author_id = db.Column(db.Integer, db.ForeignKey('author.id'))
    author = db.relationship('Author', backref='news_items')
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    content = db.Column(db.String(1024), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', back_populates='comments', overlaps="comment_author")
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), index=True)
    news = db.relationship('News', back_populates='comments')

class Picture(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    filename = db.Column(db.String(128), nullable=False, index=True)
    description = db.Column(db.String(256), nullable=True)
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), index=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)

    name = db.Column(db.String(128), nullable=False, unique=True)
    news = db.relationship('News', backref='category_items', overlaps="category,news_items")

class Author(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    bio = db.Column(db.String(1024), nullable=True)
    news = db.relationship('News', backref='news_items', lazy='dynamic')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)

    

news_tags = Table('news_tags', db.Model.metadata,
                  db.Column('news_id', db.Integer, db.ForeignKey('news.id')),
                  db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')))


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    news = db.relationship('News', secondary=news_tags, backref=db.backref('tags', lazy='dynamic'))

class Advertisement(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    title = db.Column(db.String(128), nullable=False, index=True)
    content = db.Column(db.String(1024), nullable=True)
    image_url = db.Column(db.String(256), nullable=True)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))

class SavedNews(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'))