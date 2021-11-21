import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.filters['zip'] = zip

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    total = []
    transaction = db.execute(
        "SELECT * FROM account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id", user_id=session["user_id"])
    cash_now = db.execute("SELECT cash FROM users where id=:user_id", user_id=session["user_id"])[
        0]["cash"]  # bc cash is dict {...{cash: 10000}}
    for i in reversed(transaction):
        total.append(cash_now)
        cash_now = float(i.get("price")) + cash_now
            
    return render_template("index.html", transaction=reversed(transaction), total=total)
    

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":
        if not request.form.get("password"):
            return apology("must provide current password", 403)
        elif not request.form.get("new_password"):
            return apology("must provide a new password", 403)
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 403)
        old_password = request.form.get("password")
        password = db.execute("SELECT * from users where id=:user_id", user_id=session["user_id"])
        if not check_password_hash(password[0]["hash"], (old_password)):
            return apology("invalid password", 403)
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        if old_password == new_password:
            return apology("The new password must not be the same as the old password")
        if new_password != confirmation:
            return apology("The confimation must be the same as the new password")
        hashpassword = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
        update_password = db.execute("UPDATE users SET hash = ? WHERE id= ?", hashpassword, session["user_id"])
        return redirect("/login")
    else:    
        return render_template("password.html")
    
    
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    if request.method == "POST":
        if not request.form.get("shares").isnumeric():
            return apology("Non Numeric Shares", 400)
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        elif not request.form.get("shares"):
            return apology("must provide shares", 400)
        elif int(request.form.get("shares")) < 0:
            return apology("must provide positive shares", 400)

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if lookup(symbol) is None:
            return apology("This symbol does not exist")

        quote = lookup(symbol)
        price = shares * quote['price']

        # add purchase to the table
        current_cash = db.execute("SELECT cash FROM users where id=:user_id", user_id=session["user_id"])[0]["cash"]
        if current_cash < price:
            return apology("Insufficient funds to buy stock(s)")
        addpurchase = db.execute("INSERT INTO account (symbol, name, shares, price, type) VALUES(?, ?, ?, ?, ?)", 
                                 symbol, quote['name'], shares, price, "buy")

        count = db.execute("SELECT COUNT(*) FROM account")  # [{...}]
        # print(count,type(count))
        count = int(count[0].get('COUNT(*)'))

        add_connect = db.execute("INSERT INTO connect (ID, transaction_id) VALUES(?, ?)", session['user_id'], count)

        cash_update = float(current_cash - price)
        db.execute("UPDATE users SET cash = ? WHERE id= ?", cash_update, session["user_id"])
        total = []
        transaction = db.execute(
            "SELECT * FROM account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id", user_id=session["user_id"])
        cash_now = db.execute("SELECT cash FROM users where id=:user_id", user_id=session["user_id"])[
            0]["cash"]  # bc cash is dict {...{cash: 10000}}
        for i in reversed(transaction):
            total.append(cash_now)
            cash_now = float(i.get("price")) + cash_now

        return render_template("index.html", transaction=reversed(transaction), total=total)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    total = []
    transaction = db.execute(
        "SELECT * FROM account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id", user_id=session["user_id"])
    cash_now = db.execute("SELECT cash FROM users where id=:user_id", user_id=session["user_id"])[
        0]["cash"]  # bc cash is dict {...{cash: 10000}}
    for i in reversed(transaction):
        total.append(cash_now)
        cash_now = float(i.get("price")) + cash_now
            
    return render_template("history.html", transaction=reversed(transaction), total=total)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Enter a symbol", 400)
        symbol = request.form.get("symbol")
        if lookup(symbol) is not None:
            return render_template("quoted.html", look=lookup(symbol))
        else:
            return apology("Enter a valid symbol", 400)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must be the same", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) == 1:
            return apology("username has already existed", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        hashpassword = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        rows = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashpassword)
        return redirect("/login")

    else:
        return render_template("register.html")
        

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    symbols = db.execute(
        "SELECT symboL from account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id", user_id=session["user_id"])
    symbols = [d['symboL'] for d in symbols]
    symbols_final = []
    for i in symbols:
        if i not in symbols_final:
            symbols_final.append(i)
    if request.method == "POST":
        #symbols = db.execute("SELECT symboL from account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id", user_id=session["user_id"])
        if not request.form.get("shares") or request.form.get("symbol") not in symbols_final:
            return apology("Please choose a symbol or insert shares")
        elif int(request.form.get("shares")) < 0:
            return apology("must provide positive shares", 403)
        shares = int(request.form.get("shares"))
        symbol = request.form.get("symbol")
        sum_shares = db.execute(
            "SELECT SUM(shares) from account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id and account.symboL = symbol", user_id=session["user_id"])
        sum_shares = int(sum_shares[0].get('SUM(shares)'))
        print(sum_shares, type(sum_shares))
        if shares > sum_shares:
            return apology("Not enough share")

        current_cash = db.execute("SELECT cash FROM users where id=:user_id", user_id=session["user_id"])[0]["cash"]
        quote = lookup(symbol)
        price = shares * quote['price']

        addpayment = db.execute("INSERT INTO account (symbol, name, shares, price, type) VALUES(?, ?, ?, ?, ?)", 
                                symbol, quote['name'], shares, -price, "sell")

        count = db.execute("SELECT COUNT(*) FROM account")  # [{...}]
        # print(count,type(count))
        count = int(count[0].get('COUNT(*)'))

        add_connect = db.execute("INSERT INTO connect (ID, transaction_id) VALUES(?, ?)", session['user_id'], count)

        cash_update = float(current_cash + price)
        db.execute("UPDATE users SET cash = ? WHERE id= ?", cash_update, session["user_id"])
        total = []
        transaction = db.execute(
            "SELECT * FROM account join connect on account.transaction_id = connect.transaction_id join users on connect.ID = users.id where connect.ID =:user_id", user_id=session["user_id"])
        cash_now = db.execute("SELECT cash FROM users where id=:user_id", user_id=session["user_id"])[
            0]["cash"]  # bc cash is dict {...{cash: 10000}}
        for i in reversed(transaction):
            total.append(cash_now)
            cash_now = float(i.get("price")) + cash_now
        return render_template("index.html", transaction=reversed(transaction), total=total)
    else:
        return render_template("sell.html", symbol=symbols_final)
        

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
