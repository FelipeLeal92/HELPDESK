# models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)
    role = db.Column(db.String, nullable=False, default='user')
    is_admin = db.Column(db.Boolean, default=False)
    email_updates = db.Column(db.Boolean, default=True)
    sms_urgent = db.Column(db.Boolean, default=False)
    push_realtime = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

class TicketType(db.Model):
    __tablename__ = 'ticket_types'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    description = db.Column(db.String)
    active = db.Column(db.Boolean, default=True)

class TicketStatus(db.Model):
    __tablename__ = 'ticket_statuses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    color = db.Column(db.String, default='#gray')
    active = db.Column(db.Boolean, default=True)

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String, nullable=False)
    priority = db.Column(db.String, nullable=False)
    subject = db.Column(db.String)
    description = db.Column(db.String, nullable=False)
    status = db.Column(db.String, default='Aberto')
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    closed_at = db.Column(db.DateTime(timezone=True))
    closed_by = db.Column(db.Integer)

    user = db.relationship('User', foreign_keys=[user_id])
    assignee = db.relationship('User', foreign_keys=[assigned_to])

class TicketResponse(db.Model):
    __tablename__ = 'ticket_responses'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String, nullable=False)
    is_internal = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    ticket = db.relationship('Ticket', backref=db.backref('responses', lazy=True))
    user = db.relationship('User')

class Attachment(db.Model):
    __tablename__ = 'attachments'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'))
    response_id = db.Column(db.Integer, db.ForeignKey('ticket_responses.id'))
    filename = db.Column(db.String, nullable=False)
    filepath = db.Column(db.String, nullable=False)
    filesize = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    ticket = db.relationship('Ticket', backref=db.backref('attachments', lazy=True))
    response = db.relationship('TicketResponse', backref=db.backref('attachments', lazy=True))

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'))
    message = db.Column(db.String, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    user = db.relationship('User', backref=db.backref('logs', lazy=True))
    ticket = db.relationship('Ticket')

class Setting(db.Model):
    __tablename__ = 'settings'
    key = db.Column(db.String, primary_key=True)
    value = db.Column(db.String)
