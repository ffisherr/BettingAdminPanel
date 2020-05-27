from flask import Flask, url_for, redirect, render_template, request
from flask_admin import Admin, BaseView, helpers, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_sqlalchemy import SQLAlchemy
import flask_login as login


from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from wtforms import StringField, PasswordField, BooleanField
from wtforms import SubmitField, RadioField, TextAreaField, SelectField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from wtforms.fields.html5 import EmailField, TelField


import flask_admin as admin
import bcrypt
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

username = 'root'
password = 'toor'
server   = 'localhost'
db_name  = 'betting'

# set optional bootswatch theme
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['SECRET_KEY'] = '123456790'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://%s:%s@%s/%s' % (username, password, server, db_name)
app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']= '6LcrJPwUAAAAAJ4hBSaTleqKN9FDzxSVch_8i0so'
app.config['RECAPTCHA_PRIVATE_KEY']='6LcrJPwUAAAAAMo_wcrlC1SB7Hv3lgIGlhcFXX19'
app.config['RECAPTCHA_OPTIONS'] = {'theme':'white'}


db = SQLAlchemy(app)


AGENT 	  = 'agent'
MANAGERS  = 'moderator'
ADMIN 	  = 'administrator'

class Bets(db.Model):
	id = db.Column(db.Integer, primary_key=True, unique=True)
	sport = db.Column(db.String)
	event = db.Column(db.String)
	match = db.Column(db.String)
	selection = db.Column(db.String)
	created_at  = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)	
	time_out = db.Column(db.DateTime)
	bookmaker = db.Column(db.String)


class Chats(db.Model):
	id = db.Column(db.Integer, primary_key=True, unique=True)
	chat_name =  db.Column(db.String)
	created_at  = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)	
	chats      = db.relationship('UserChats', backref='chat', lazy='dynamic')


class Bookmakers(db.Model):
	id = db.Column(db.Integer, primary_key=True, unique=True)
	bookmaker_name =  db.Column(db.String)
	created_at  = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)	


class Users(db.Model):
	id    	 = db.Column(db.Integer, primary_key=True, unique=True)
	email    = db.Column(db.String)
	password = db.Column(db.String)
	first_name = db.Column(db.String)
	last_name  = db.Column(db.String)
	phone      = db.Column(db.String)
	status_id  = db.Column(db.Integer)
	created_at  = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)
	roles      = db.relationship('UserRoles', backref='user', lazy='dynamic')
	chats      = db.relationship('UserChats', backref='user', lazy='dynamic')


	def verify_password(self, password):
		return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

	@property
	def is_authenticated(self):
		return True

	@property
	def is_active(self):
		return True

	@property
	def is_anonymous(self):
		return False

	def get_id(self):
		return self.id

	# Required for administrative interface
	def __unicode__(self):
		return self.email

	def __repr__(self):
		return '<User %r>' % self.email


class Roles(db.Model):
	id         = db.Column(db.Integer, primary_key=True, unique=True)
	role_name  = db.Column(db.String)
	created_at = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)	
	user_roles = db.relationship('UserRoles', backref='role', lazy='dynamic')


class UserRoles(db.Model):
	id         = db.Column(db.Integer, primary_key=True, unique=True)
	user_id    = db.Column(db.Integer, db.ForeignKey('users.id'))
	role_id    = db.Column(db.Integer, db.ForeignKey('roles.id'))
	created_at = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)


class UserChats(db.Model):
	id = db.Column(db.Integer, primary_key=True, unique=True)
	chat_id    = db.Column(db.Integer, db.ForeignKey('chats.id'))
	user_id    = db.Column(db.Integer, db.ForeignKey('users.id'))
	created_at = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)


class UserMessages(db.Model):
	id = db.Column(db.Integer, primary_key=True, unique=True)
	chat_id    = db.Column(db.Integer, db.ForeignKey('chats.id'))
	FROM       = db.Column(db.Integer)
	to         = db.Column(db.Integer)
	text  	   = db.Column(db.String)
	created_at = db.Column(db.DateTime)
	updated_at = db.Column(db.DateTime)
	deleted_at = db.Column(db.DateTime)



def getUserRole(user_id):
	user_role = UserRoles.query.filter_by(user_id=user_id).first()
	return user_role.role.role_name


def chooseFrom(r_users, USER_ROLE):
	_result_users_set = []
	for r_user in r_users:
		if USER_ROLE == getUserRole(r_user.id):
			_result_users_set.append(r_user)
	return _result_users_set


def getCommonChat(user1, user2):
	chats1 = UserChats.query.filter_by(user_id=user1.id).all()
	chats2 = UserChats.query.filter_by(user_id=user2.id).all()
	commonChats = []
	if len(chats1) == 0 or len(chats2) == 0:
		return commonChats
	for _chat in chats1:
		z = True
		for _ch2 in chats2:
			if _ch2.chat_id != _chat.chat_id:
				z = False
		if z == True:
			commonChats.append(_chat.chat_id)
	return commonChats

def getPrivateChat(user1, user2, commonChats):
	if commonChats is not None and len(commonChats) > 0:
		for _chat in commonChats:
			uchat = UserChats.query.filter_by(chat_id=_chat).all()
			if len(uchat) == 2:
				return uchat[0].chat_id
	chat_name = 'Личный чат %s с %s' % (user1.email, user2.email)
	uch = Chats(chat_name=chat_name)
	db.session.add(uch)
	db.session.commit()
	uch = Chats.query.filter_by(chat_name=chat_name).first()
	user1Chat = UserChats(chat_id=uch.id, user_id=user1.id)
	user2Chat = UserChats(chat_id=uch.id, user_id=user2.id)
	db.session.add(user1Chat)
	db.session.add(user2Chat)
	db.session.commit()
	return uch.id


def createMessage(u_from, u_to, _text, chat_id):
	m = UserMessages(chat_id=chat_id, FROM=u_from, to=u_to, text=_text)
	db.session.add(m)
	db.session.commit()


def sendNotificationTo(users, text):
	curr = login.current_user
	for _u in users:
		target_user = Users.query.filter_by(id=_u).first()
		p_chat_id = getPrivateChat(curr, target_user, getCommonChat(curr, target_user))
		createMessage(curr.id, _u, text, p_chat_id)



def createUserRole(user_id, role_name):
	_role = Roles.query.filter_by(role_name=role_name).first()
	ur = UserRoles(user_id=user_id, role_id=_role.id)
	db.session.add(ur)
	db.session.commit()

# Define login and registration forms (for flask-login)
class LoginForm(FlaskForm):
	login 	 = StringField('Email', validators=[Required()])
	password = PasswordField('Пароль', validators=[Required()])
	recaptcha = RecaptchaField()

	def validate_login(self, field):
		user = self.get_user()

		if user is None:
			raise ValidationError('Пользователя не существует')

		if user.verify_password(self.password.data) == False:
			raise ValidationError('Неверный пароль')

	def get_user(self):
		return db.session.query(Users).filter_by(email=self.login.data).first()


class RegistrationForm(FlaskForm):
	email 			= StringField('Email', validators=[Required()])
	first_name	    = StringField('Имя', validators=[Required()])
	last_name       = StringField('Фамилия', validators=[Required()])
	phone           = TelField('Телефон', validators=[Required()])
	password 	    = PasswordField('Пароль', validators=[Required()])
	repeat_password = PasswordField('Повторить пароль', validators=[Required()])
	recaptcha = RecaptchaField()

	def validate_login(self, field):
		if db.session.query(Users).filter_by(email=self.email.data).count() > 0:
			raise ValidationError('Пользователь уже существует')
		if self.password.data != self.repeat_password.data:
			raise ValidationError('Введенные пароли не совпадают')


# Create customized index view class that handles login & registration
class MyAdminIndexView(admin.AdminIndexView):

	@expose('/')
	def index(self):
		if not login.current_user.is_authenticated:
			return redirect(url_for('.login_view'))
		return super(MyAdminIndexView, self).index()

	@expose('/login/', methods=('GET', 'POST'))
	def login_view(self):
		# handle user login
		form = LoginForm(request.form)
		if helpers.validate_form_on_submit(form):
			user = form.get_user()
			login.login_user(user)
		if login.current_user.is_authenticated:
			return redirect(url_for('.index'))
		link = '<p>Нет аккаунта? <a href="' + url_for('.register_view') + '">Нажмите чтобы зарегестрироваться.</a></p>'
		self._template_args['form'] = form
		self._template_args['link'] = link
		return super(MyAdminIndexView, self).index()

	@expose('/register/', methods=('GET', 'POST'))
	def register_view(self):
		form = RegistrationForm(request.form)
		if helpers.validate_form_on_submit(form):
			user = Users(status_id=2)

			form.populate_obj(user)
			
			if form.password.data != form.repeat_password.data:
				link = '<p>Пароли не совпадают!</p></br>\
				<p>Уже есть аккаунт? <a href="' + url_for('.login_view') + '">Нажмите здесь чтобы войти.</a></p>'
				self._template_args['link'] = link
				self._template_args['form'] = form
				return super(MyAdminIndexView, self).index()

			user.password = bcrypt.hashpw(password=form.password.data.encode('utf-8'), salt=bcrypt.gensalt())
			db.session.add(user)
			db.session.commit()
			_u = Users.query.filter_by(email=user.email).first()
			createUserRole(_u.id, AGENT)

			login.login_user(user)
			return redirect(url_for('.index'))
		link = '<p>Уже есть аккаунт? <a href="' + url_for('.login_view') + '">Нажмите здесь чтобы войти.</a></p>'
		self._template_args['form'] = form
		self._template_args['link'] = link
		return super(MyAdminIndexView, self).index()

	@expose('/logout/')
	def logout_view(self):
		login.logout_user()
		return redirect(url_for('.index'))


# Initialize flask-login
def init_login():
	login_manager = login.LoginManager()
	login_manager.init_app(app)

	# Create user loader function
	@login_manager.user_loader
	def load_user(user_id):
		return db.session.query(Users).get(user_id)

init_login()


# Flask views
@app.route('/')
def index():
	return render_template('index.html')

class AgentsModelView(BaseView):
	
	@expose('/', methods=('POST', 'GET'))
	def index(self):
		agents = Users.query.all()
		result = chooseFrom(agents, AGENT)
		if request.method == 'POST':
			checks = []
			for _u in result:
				if (request.form.get('check_%s' % _u.id)):
					checks.append(_u.id)
			if len(checks) > 0:
				sendNotificationTo(checks, request.form.get('push_notification'))
			return redirect(url_for('.index'))
		table_description = 'Таблица Агентов'
		return self.render('edit_user.html', users=result, allow_to_create=True,
			table_description=table_description, context='agents',
			current=login.current_user, curr_role=getUserRole(login.current_user.id))
	
	@expose('/create/', methods=('POST', 'GET'))
	def create_user(self):
		u = Users()
		if request.method == 'POST':
			u.status_id   = 2
			u.email       = request.form.get('email')
			u.first_name  = request.form.get('first_name')
			u.last_name   = request.form.get('last_name')
			u.phone       = request.form.get('phonenumber')
			u.password = bcrypt.hashpw(password=request.form.get('password_1').encode('utf-8'), salt=bcrypt.gensalt())
			db.session.add(u)
			db.session.commit()
			_u = Users.query.filter_by(email=u.email).first()
			createUserRole(_u.id, AGENT)
			return redirect(url_for('.index'))
		u.email 	 = ''
		u.first_name = ''
		u.last_name  = ''
		u.phone      = ''
		return self.render('edit_user_info.html', _u=u, create_user=True)

	@expose('/delete_user/<int:id>')
	def delete_user(self, id):
		u = Users.query.filter_by(id=id).first()
		db.session.delete(u)
		db.session.commit()
		return redirect(url_for('.index'))

	@expose('/edit_user/<int:id>', methods=('POST', 'GET'))
	def edit_user(self, id):
		u = Users.query.filter_by(id=id).first()
		if request.method == 'POST':
			u.status_id   = 2
			u.email       = request.form.get('email')
			u.first_name  = request.form.get('first_name')
			u.last_name   = request.form.get('last_name')
			u.phone       = request.form.get('phonenumber')
			db.session.add(u)
			db.session.commit()
			return redirect(url_for('.index'))
		return self.render('edit_user_info.html', _u=u, create_user=False)

	def is_accessible(self):
		return login.current_user.is_authenticated and (ADMIN == getUserRole(login.current_user.id)\
			or MANAGERS ==  getUserRole(login.current_user.id))

class ManagersModelView(BaseView):
	
	@expose('/', methods=('POST', 'GET'))
	def index(self):
		managers = Users.query.all()
		result = chooseFrom(managers, MANAGERS)
		if request.method == 'POST':
			checks = []
			for _u in result:
				if (request.form.get('check_%s' % _u.id)):
					checks.append(_u.id)
			if len(checks) > 0:
				sendNotificationTo(checks, request.form.get('push_notification'))
			return redirect(url_for('.index'))
		table_description = 'Таблица Менеджеров'
		return self.render('edit_user.html', users=result, allow_to_create=True,
			table_description=table_description, context='managers',
			current=login.current_user, curr_role=getUserRole(login.current_user.id))

	@expose('/create/', methods=('POST', 'GET'))
	def create_user(self):
		u = Users()
		if request.method == 'POST':
			u.status_id   = 2
			u.email       = request.form.get('email')
			u.first_name  = request.form.get('first_name')
			u.last_name   = request.form.get('last_name')
			u.phone       = request.form.get('phonenumber')
			u.password = bcrypt.hashpw(password=request.form.get('password_1').encode('utf-8'), salt=bcrypt.gensalt())
			db.session.add(u)
			db.session.commit()
			_u = Users.query.filter_by(email=u.email).first()
			createUserRole(_u.id, MANAGERS)
			return redirect(url_for('.index'))
		u.email 	 = ''
		u.first_name = ''
		u.last_name  = ''
		u.phone      = ''
		return self.render('edit_user_info.html', _u=u, create_user=True)

	@expose('/delete_user/<int:id>')
	def delete_user(self, id):
		u = Users.query.filter_by(id=id).first()
		db.session.delete(u)
		db.session.commit()
		return redirect(url_for('.index'))

	@expose('/edit_user/<int:id>', methods=('POST', 'GET'))
	def edit_user(self, id):
		u = Users.query.filter_by(id=id).first()
		if request.method == 'POST':
			u.status_id   = 2
			u.email       = request.form.get('email')
			u.first_name  = request.form.get('first_name')
			u.last_name   = request.form.get('last_name')
			u.phone       = request.form.get('phonenumber')
			db.session.add(u)
			db.session.commit()
			return redirect(url_for('.index'))
		return self.render('edit_user_info.html', _u=u)

	def is_accessible(self):
		return login.current_user.is_authenticated and (ADMIN ==  getUserRole(login.current_user.id))


class PersonalAreaModelView(BaseView):
	
	@expose('/')
	def index(self):
		table_description = 'Личный кабинет'
		c_user = Users.query.filter_by(id=login.current_user.id).first()
		return self.render('edit_user.html', users=[c_user], allow_to_create=False,
			table_description=table_description, context='personal_area', current=login.current_user)

	@expose('/delete_user/<int:id>')
	def delete_user(self, id):
		u = Users.query.filter_by(id=login.current_user.id).first()
		db.session.delete(u)
		db.session.commit()
		return redirect(url_for('.index'))

	@expose('/edit_user/<int:id>', methods=('POST', 'GET'))
	def edit_user(self, id):
		u = User.query.filter_by(id=login.current_user.id).first()
		if request.method == 'POST':
			if u.verify_password(request.form.get('old_password')) == False:
				warnings = 'Введен неверный старый пароль'
				return self.render('edit_user_info.html', _u=u, warnings=warnings, personal=True)
			if request.form.get('new_password_1') != request.form.get('new_password_2'):
				warnings = 'Введенные пароли не совпадают'
				return self.render('edit_user_info.html', _u=u, warnings=warnings, personal=True)				
			u.email       = request.form.get('email')
			u.status_id   = 2
			u.first_name  = request.form.get('first_name')
			u.last_name   = request.form.get('last_name')
			u.phone       = request.form.get('phonenumber')
			u.password = bcrypt.hashpw(password=request.form.get('new_password_1').encode('utf-8'), salt = bcrypt.gensalt())
			db.session.add(u)
			db.session.commit()
			return redirect(url_for('.index'))
		return self.render('edit_user_info.html', _u=u, personal=True)

	def is_accessible(self):
		return login.current_user.is_authenticated

class AdminModelView(ModelView):
	excluded_list_columns = ('id', 'created_at', 'updated_at',
		'deleted_at',)
	form_excluded_columns = ['created_at', 'updated_at',
		'deleted_at',]

	def is_accessible(self):
		return (login.current_user.is_authenticated and getUserRole(login.current_user.id) == ADMIN)


class ExitView(BaseView):
	@expose('/')
	def index(self):
		return redirect('/admin/logout/')

	def is_accessible(self):
		return login.current_user.is_authenticated



class ChatsModelView(BaseView):
	
	@expose('/')
	def index(self):
		chats = Chats.query.all()
		if (getUserRole(login.current_user.id) == ADMIN):
			return self.render('chats_list.html', chats=chats)
		uc = UserChats.query.filter_by(user_id=login.current_user.id).all()
		chats = []
		for _chat in uc:
			newChat = Chats.query.filter_by(id=_chat.chat_id).first()
			if newChat not in chats:
				chats.append(newChat)
		return self.render('chats_list.html', chats=chats,
			agent=(getUserRole(login.current_user.id) == AGENT))

	@expose('/about/<int:id>')
	def about(self, id):
		chats = Chats.query.filter_by(id=id).first()
		messages = []
		ms = UserMessages.query.filter_by(chat_id=id).all()
		if len(ms) > 0:
			for m in ms:
				sender = Users.query.filter_by(id=m.FROM).first()
				messages.append([sender.email, m])
		return self.render('chat.html', chat=chats, admin=(getUserRole(login.current_user.id) == ADMIN), messages=messages)

	@expose('/delete/message/<int:id>')
	def delete(self, id):
		if getUserRole(login.current_user.id) != ADMIN:
			return redirect(url_for('.index'))
		message = UserMessages.query.filter_by(id=id).first()
		db.session.delete(message)
		db.session.commit()
		return redirect(url_for('.index'))


	@expose('/send_message', methods=('GET', 'POST'))
	def send_message(self):
		if request.method == 'POST':
			email = request.form.get('email')
			text  = request.form.get('message_text')
			target = Users.query.filter_by(email=email).first()
			if target is not None:
				p_chat_id = getPrivateChat(login.current_user, target, getCommonChat(login.current_user, target))
				createMessage(login.current_user.id, target.id, text, p_chat_id)
			return redirect(url_for('.index'))
		return self.render('send_message.html')

	def is_accessible(self):
		return login.current_user.is_authenticated


admin = Admin(app, name='Панель администратора', index_view=MyAdminIndexView(), template_mode='bootstrap3')
admin.add_view(AgentsModelView(name='Агенты', endpoint='agents'))
admin.add_view(ManagersModelView(name='Менеджеры', endpoint='managers'))
admin.add_view(AdminModelView(Bets, db.session, name='Ставки'))
admin.add_view(AdminModelView(Bookmakers, db.session, name='Букмекеры'))
admin.add_view(ChatsModelView(name="Чаты", endpoint='chats'))
admin.add_view(PersonalAreaModelView(name='Личный кабинет', endpoint='personal_area'))
admin.add_view(ExitView(name='Выход'))


if __name__ == '__main__':
	app.run(debug=True)
