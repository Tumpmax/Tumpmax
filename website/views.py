import os
import pandas as pd
import json
import time
import csv
import smtplib
import sqlite3
import plotly.express as px
import shutil
import glob
from os import path
from sqlalchemy import sql
from sqlalchemy.exc import IntegrityError
from flask import Blueprint, render_template, url_for, flash, redirect, request, abort
from werkzeug.utils import secure_filename
from wtforms.validators import Email
from website.forms import SignupForm, LoginForm, UpdateAccountForm, CryptoForm, EmailForm
from website.models import User, Crypto
from flask_login import login_user, current_user, logout_user, login_required
from website import db, bcrypt
from requests_html import HTMLSession
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv



views = Blueprint('views', __name__)


@views.route('/signup', methods=['GET', 'POST'])
def sign_up():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('views.login'))
    return render_template('signup.html', title='Signup', form=form)


@views.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('views.home'))

        elif user is not None:
            with open('login_attempts.log', 'a') as Attempt:
                pass
            with open('blacklist.log', 'a') as BlackL:
                pass

                with open('blacklist.log', 'r+') as BlackL:
                    for BL in BlackL:
                        if form.email.data == BlackL: #This one checks if username in blacklist
                            print(BL)
                            flash("Account is locked, please contact the admin.")
                            return render_template('disabled_login.html', form=form)

                with open('login_attempts.log', 'r+') as Attempt:
                        for  line in range(3):
                            line = int(line)
                            filesize = os.path.getsize("login_attempts.log")
                            if filesize == 0:
                                if line == 0:
                                    new_line = line + 1
                                    Attempt.write(str(new_line))
                                    flash("Attempt: " + str(new_line))
                                    flash("Email or Password is incorrect")
                                    return render_template("login.html", title='Login', form=form, user=current_user)

                            new_line = Attempt.readlines()
                            with open('login_attempts.log', 'w') as Attempt:
                                for i in new_line:
                                    if i.strip("\n") != "2":
                                        new_line2 = int(i) + 1
                                        str_newline2 = str(new_line2) 
                                        Attempt.write(str_newline2)
                                        flash("Attempt: " + str_newline2)
                                        flash("Email or Password is incorrect")
                                        return render_template("login.html", title='Login', form=form, user=current_user)

                            with open('login_attempts.log', 'w') as Attempt:
                                for i in new_line:
                                    if i.strip("\n") != "3":
                                        new_line3 = int(i) + 1
                                        str_newline3 = str(new_line3) 
                                        Attempt.write(str_newline3)
                                    if int(str_newline3) == 3:
                                        flash("Attempt: " + str_newline3)
                                        flash("Account is locked. Please contact admin.")
                                        with open('blacklist.log', 'r+') as BlackL:
                                                BlackL.write(form.email.data)
                                                return render_template("disabled_login.html", title='Login', form=form, user=current_user)
                                                
    return render_template("login.html", title='Login', form=form, user=current_user)


@views.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('views.login'))

@views.route('/')
@login_required
def home():
    return render_template("home.html")


@views.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('views.home'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('update_account.html', title='Account', form=form)


@views.route('/crypto', methods=['GET', 'POST'])
@login_required
def scrapedata():

    #input ticker data - based on Yahoo Finance ticker symbols  
    form = CryptoForm()
    if form.validate_on_submit():
        form_data = Crypto(crypto=form.crypto.data)
        tag = form_data.crypto
        URL = f'https://query1.finance.yahoo.com/v7/finance/quote?&symbols={tag}'
        s = HTMLSession()
        r = s.get(URL)
        print(r.status_code)
        data_json = r.json() 
        stock_d = json.dumps(data_json)
        stocks_str = json.loads(stock_d)
        #loop writing crypto data to csv file
        for stock_data in stocks_str['quoteResponse']['result']:
            active_price = stock_data['regularMarketPrice']
            name = stock_data['shortName']
            crypto_info = Crypto(crypto=name, crypto_data=active_price)
            db.session.add(crypto_info)
            db.session.commit()
            flash('Your data has been downloaded!', 'success')
            return render_template('crypto.html', form=form)
    return render_template('crypto.html', title='Crypto Ticker', form=form)

@views.route('/crypto/results/email', methods=['GET', 'POST'])
@login_required
def email():
    connection = sqlite3.connect("website/database.db")
    df = pd.read_sql('select * from cryptos', connection)
    df.to_csv('Crypto_Ledger.csv')
    if not path.exists('Crypto_Ledger.csv'):
        flash('No file available! Please download file first.', 'warning')
        return redirect(url_for('views.home'))
        
    #create a config.env file to input EMAIL_USER & EMAIL_PASS
    #form = EmailForm()
    #if form.validate_on_submit():
        #EMAIL_ADDRESS = form.sender_email.data
        #EMAIL_PASSWORD = form.sender_password.data
        #RECIPIENT = form.recipient_email.data
    EMAIL_ADDRESS = os.environ.get('GMAIL_SMTP_USER')
    EMAIL_PASSWORD = os.environ.get('GMAIL_SMTP_PASSWORD')

    RECIPIENT = os.environ.get('RECEIVER')

    msg = MIMEMultipart('mixed')

    msg['Subject'] = 'Crypto Info'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = RECIPIENT

    filename = 'Crypto_Ledger.csv'
    with open('Crypto_Ledger.csv', 'rb') as attachment:
            csv = MIMEBase('text','csv')
            csv.set_payload(attachment.read())
            encoders.encode_base64(csv)
            csv.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(csv)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
            
    time.sleep(5)
    os.remove('Crypto_Ledger.csv')
    flash('Your file has been emailed!', 'success')
    #return render_template('send_email.html', form=form, user=current_user)
    return redirect(url_for('views.home'))

@views.route('/crypto/results')
@login_required
def results():
    #load_dotenv('config.env')
    query_data = Crypto.query.all()

    for data in query_data:
        data.crypto
        data.crypto_data
        data.datestp
        return render_template('results.html', data=data, query_data=query_data, user=current_user)
    return render_template('results.html', query_data=query_data, user=current_user)

@views.route('/crypto/results/create_graph')
@login_required
def generate_graph():
    connection = sqlite3.connect("website/database.db")
    df = pd.read_sql('select * from cryptos', connection)
    fig = px.scatter(df, title='Crypto Currencies', x='datestp', y='crypto_data', color='crypto')
    fig.update_traces(marker=dict(size=12,
                              line=dict(width=2,
                                        color='DarkSlateGrey')),
                  selector=dict(mode='markers'))
    fig.write_html('crypto_graph.html')
    time.sleep(3)
    shutil.move('crypto_graph.html', 'website/templates/crypto_graph.html')
    flash("Graph has been generated", 'success')
    return redirect(url_for('views.home'))


@views.route('/crypto/results/show_graph')
@login_required
def show_graph():
    return render_template('crypto_graph.html', user=current_user)


@views.route('crypto/upload')
def upload_file():
   return render_template('upload.html')
	
@views.route('crypto/uploader', methods = ['GET', 'POST'])
def uploader_file():
   if request.method == 'POST':
      f = request.files['file']
      f.save(secure_filename(f.filename))
      flash('File uploaded successfully', 'success')
      return redirect(url_for('views.home'))

@views.route('crypto/convert_file', methods = ['GET', 'POST'])
def convert_file():
    path = os.getcwd()
    csv_files = glob.glob(os.path.join(path, "*.csv" or "*.xls"))
  
  
    # loop over the list of csv files
    for f in csv_files:
        
        # read the csv file
        df = pd.read_csv(f)
        
        # print the location and filename
        #print('Location:', f)
        #print('File Name:', f.split("\\")[-1])
    
    fig = px.scatter(df, title='Crypto Currencies', x='Time Stamp', y='Active Price', color='Crypto')
    fig.update_traces(marker=dict(size=12,
                              line=dict(width=2,
                                        color='DarkSlateGrey')),
                  selector=dict(mode='markers'))
    fig.write_html('Crypto_ledger.html')
    time.sleep(3)
    shutil.move('Crypto_ledger.html', 'website/templates/Crypto_ledger.html')
    return render_template('Crypto_ledger.html', user=current_user)
