#!venv/bin/python
import os
from flask import Flask, url_for, redirect, render_template, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_security.utils import encrypt_password
import flask_admin
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from flask_admin import BaseView, expose
from datetime import datetime
from wtforms.validators import AnyOf
import pymysql

pymysql.install_as_MySQLdb()

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')
# app.config[SESSION_SQLALCHEMY_TABLE] = 'sessions'
# app.config[SESSION_SQLALCHEMY] = db
db = SQLAlchemy(app)
# session = Session(app)
# session.app.session_interface.db.create_all()

# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    orders = db.relationship('Order',backref='sales',lazy=True)

    def __str__(self):
        return self.email

class Branch(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    branch_code = db.Column(db.String(10))
    branch_desc = db.Column(db.String(50))
    # cars = db.relationship('Car',backref='branch',lazy=True)
    cars = db.relationship('Car',backref='branch_car',lazy=True)
    orders = db.relationship('Order',backref='branch_order',lazy=True)

    def __str__(self):
        return self.branch_desc

class Order(db.Model):
    __tablename__ = 'order'
    __mapper_args__ = {'polymorphic_identity': 'order'}
    id = db.Column(db.Integer,primary_key=True)
    # order_date = db.Column(db.DateTime,default = datetime.strftime(datetime.today(), "%d-%m-%Y"))
    order_date = db.Column(db.DateTime())
    source = db.Column(db.String(20))
    # order_date = db.Column(db.String(12))
    customer_name = db.Column(db.String(50))
    customer_address = db.Column(db.String(50))
    customer_phone = db.Column(db.String(13))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=True)
    car_id = db.Column(db.Integer,db.ForeignKey('car.id'),nullable=False)
    qualified_id = db.Column(db.Integer,db.ForeignKey('qualified_order.id'),nullable=True)
    branch_id = db.Column(db.Integer,db.ForeignKey('branch.id'),nullable=True)

    def __str__(self):
        return self.customer_name + ' ' + self.car_id
        
class SevaOrder(Order):
    __tablename__ = 'seva_order'
    __mapper_args__ = {'polymorphic_identity': 'seva_order'}
    id = db.Column(db.Integer,db.ForeignKey('order.id'),primary_key=True)
    seva_order_id = db.Column(db.String(50))
    event = db.Column(db.String(50))
    kode_voucher = db.Column(db.String(50))
    bundling = db.Column(db.String(50))

class M88Order(Order):
    __tablename__ = 'm88_order'
    __mapper_args__ = {'polymorphic_identity': 'm88_order'}
    id = db.Column(db.Integer,db.ForeignKey('order.id'),primary_key=True)
    m88_order_id = db.Column(db.String(50))
    appointment = db.Column(db.DateTime())

class QualifiedOrder(Order):
    __tablename__ = 'qualified_order'
    __mapper_args__ = {'polymorphic_identity': 'qualified_order'}
    id = db.Column(db.Integer,primary_key=True)
    receive = db.Column(db.DateTime())
    update = db.Column(db.DateTime())
    appointment = db.Column(db.DateTime())
    walkin = db.Column(db.DateTime())
    orders = db.relationship('Order',backref='order',lazy=True)
    
class Car(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    brand = db.Column(db.String(50))
    tipe = db.Column(db.String(50))
    varian = db.Column(db.String(50))
    fuel = db.Column(db.String(50))
    transmission = db.Column(db.String(50))
    plate_no = db.Column(db.String(15))
    branch_id = db.Column(db.Integer,db.ForeignKey('branch.id'),nullable=False,)
    orders = db.relationship('Order',backref='car',lazy=True)

    def __str__(self):
        return self.brand + ' ' + self.tipe + ' ' + self.varian + ' ' + self.fuel + ' ' + self.transmission + ' ' + self.plate_no

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Create customized model view class
class MyModelView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        if current_user.has_role('superuser'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


    # can_edit = True
    edit_modal = True
    create_modal = True    
    can_export = True
    can_view_details = True
    details_modal = True


# Create seva model view class
class SevaModelView(sqla.ModelView):
    form_args = {
        '': {
            'validators': [AnyOf(['seva',])]
        }
    }

    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        if current_user.has_role('seva'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


    can_edit = True
    edit_modal = True
    create_modal = True    
    can_export = True
    can_view_details = True
    details_modal = True

# Create seva model view class
class M88ModelView(sqla.ModelView):
    form_args = {
        '': {
            'validators': [AnyOf(['m88',])]
        }
    }
    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        if current_user.has_role('m88'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


    can_edit = False
    edit_modal = True
    create_modal = True    
    can_export = True
    can_view_details = True
    details_modal = True

# Create sales model view class
class SalesModelView(sqla.ModelView):
    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        if current_user.has_role('sales'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

    
    # userId = current_user.get_id()
    form_args = {
        '': {
            'validators': [AnyOf(['sales'])]
        }
    }
    can_edit = False
    edit_modal = True
    create_modal = True    
    can_export = True
    can_view_details = True
    details_modal = True

class UserView(MyModelView):
    column_editable_list = ['email', 'first_name', 'last_name']
    column_searchable_list = column_editable_list
    column_exclude_list = ['password']
    # form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list

class BranchView(MyModelView):
    column_editable_list = ['branch_code']
    column_searchable_list = column_editable_list
    column_exclude_list = ['cars']
    form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list

class CarView(MyModelView):
    column_editable_list = ['plate_no','branch_id']
    column_searchable_list = column_editable_list
    column_exclude_list = ['orders']
    form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = ['brand','tipe','varian','fuel','transmission']

class OrderView(MyModelView):
    edit_columns = ['user_id']
    column_editable_list = ['user_id']
    column_searchable_list = column_editable_list
    edit_exclude_columns = ['customer_name']
    # column_exclude_list = ['password']
    # form_excluded_columns = column_exclude_list
    # column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list

class SevaOrderView(SevaModelView):
    column_editable_list = ['customer_name','customer_address','customer_phone']
    column_searchable_list = column_editable_list
    column_exclude_list = ['user','order','sales']
    form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list

class M88OrderView(M88ModelView):
    column_editable_list = ['customer_name','customer_address','customer_phone','branch_id']
    column_searchable_list = column_editable_list
    column_exclude_list = ['sales','source','order']
    form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list

class SalesOrderView(SalesModelView):
    column_editable_list = ['receive','update','appointment','walkin']
    column_searchable_list = column_editable_list
    column_exclude_list = []
    form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list


class CustomView(BaseView):
    @expose('/')
    def index(self):
        return self.render('admin/custom_index.html')

# Flask views
@app.route('/')
def index():
    return render_template('index.html')

# Create admin
admin = flask_admin.Admin(
    app,
    'My Dashboard',
    base_template='my_master.html',
    template_mode='bootstrap3',
)

# Add model views
admin.add_view(MyModelView(Role, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Roles"))
admin.add_view(UserView(User, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Users"))
admin.add_view(BranchView(Branch, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Branches"))
admin.add_view(CarView(Car, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Cars"))
admin.add_view(OrderView(Order, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Orders"))
admin.add_view(SevaOrderView(SevaOrder, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="SevaOrders"))
admin.add_view(M88OrderView(M88Order, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="M88Orders"))
admin.add_view(SalesOrderView(QualifiedOrder, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="QualifiedOrders"))
admin.add_view(CustomView(name="Custom view", endpoint='custom', menu_icon_type='fa', menu_icon_value='fa-connectdevelop',))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )

def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    import string
    import random

    # db.drop_all()
    # db.create_all()

    # with app.app_context():
    #     user_role = Role(name='user')
    #     super_user_role = Role(name='superuser')
    #     db.session.add(user_role)
    #     db.session.add(super_user_role)
    #     db.session.commit()

    #     test_user = user_datastore.create_user(
    #         first_name='Admin',
    #         email='admin',
    #         password=encrypt_password('admin'),
    #         roles=[user_role, super_user_role]
    #     )

    #     first_names = [
    #         'Harry', 'Amelia', 'Oliver', 'Jack', 'Isabella', 'Charlie', 'Sophie', 'Mia',
    #         'Jacob', 'Thomas', 'Emily', 'Lily', 'Ava', 'Isla', 'Alfie', 'Olivia', 'Jessica',
    #         'Riley', 'William', 'James', 'Geoffrey', 'Lisa', 'Benjamin', 'Stacey', 'Lucy'
    #     ]
    #     last_names = [
    #         'Brown', 'Smith', 'Patel', 'Jones', 'Williams', 'Johnson', 'Taylor', 'Thomas',
    #         'Roberts', 'Khan', 'Lewis', 'Jackson', 'Clarke', 'James', 'Phillips', 'Wilson',
    #         'Ali', 'Mason', 'Mitchell', 'Rose', 'Davis', 'Davies', 'Rodriguez', 'Cox', 'Alexander'
    #     ]

    #     for i in range(len(first_names)):
    #         tmp_email = first_names[i].lower() + "." + last_names[i].lower() + "@example.com"
    #         tmp_pass = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(10))
    #         user_datastore.create_user(
    #             first_name=first_names[i],
    #             last_name=last_names[i],
    #             email=tmp_email,
    #             password=encrypt_password(tmp_pass),
    #             roles=[user_role, ]
    #         )
        # db.session.commit()
    return

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    # database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    # if not os.path.exists(database_path):
        # build_sample_db()
    build_sample_db()

    # Start app
    app.run(debug=True)