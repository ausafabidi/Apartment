import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, inr

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["inr"] = inr

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///apartment.db")

# Make sure API key is set
#if not os.environ.get("API_KEY"):
    #raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def home():
    """Show home page"""
    return render_template("home.html")


@app.route("/directory")
@login_required
def directory():
    """Show directory of residents"""
    rows = db.execute("SELECT * FROM residents WHERE flat > 100 ORDER BY flat ASC")
    return render_template("directory.html", rows=rows)

@app.route("/admin")
@login_required
def admin():
    """Show directory of admins"""
    rows = db.execute("SELECT * FROM residents WHERE flat < 101 ORDER BY flat ASC")
    return render_template("admin.html", rows=rows)

@app.route("/security")
@login_required
def security():
    """Show directory of Security staff"""
    return render_template("security.html")


#Feedback starts
@app.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback():
    """Manage suggestion book"""
    flat=session["user_id"]
    #Checking if resident posted the comment
    if request.method == "POST" and int(flat)>100:
        now=datetime.datetime.now()
        subject=request.form.get("subject")
        feedback=request.form.get("feedback")
        db.execute("INSERT INTO feedback (flat, datetime, subject, feedback, status) VALUES (?, ?, ?, ?, ?)",
            flat, now, subject, feedback, 'Open')
        rows = db.execute("SELECT * FROM feedback WHERE status = :status ORDER BY datetime DESC", status='Open')
        return render_template("feedback_book.html", rows=rows)

    elif request.method == "GET" and int(flat)<100:
        rows = db.execute("SELECT * FROM feedback ORDER BY datetime DESC")
        return render_template("feedback_book_admin.html", rows=rows)


    else:
        rows = db.execute("SELECT * FROM feedback WHERE status = :status", status='Open')
        return render_template("feedback_book.html", rows=rows)

@app.route("/feedback_todo", methods=["GET", "POST"])
@login_required
def feedbacktodo():
    """Manage suggestion book"""
    return render_template("feedback.html")

@app.route("/feedback_more", methods=["GET", "POST"])
@login_required
def feedback_more():
    """Manage suggestion book"""
    flat=session["user_id"]
    if request.method == "POST" and int(flat)>100:
        datetime=request.form.get("name")
        rows = db.execute("SELECT * FROM feedback WHERE datetime = :datetime ORDER BY datetime DESC", datetime=datetime)
        return render_template("feedback_more.html", rows=rows, name=datetime)

    elif request.method == "POST" and int(flat)<100:
        datetime=request.form.get("name")
        rows = db.execute("SELECT * FROM feedback WHERE datetime = :datetime ORDER BY datetime DESC", datetime=datetime)
        return render_template("feedback_more_admin.html", rows=rows)
    else:
        return render_template("feedback.html")

@app.route("/feedback_close", methods=["GET", "POST"])
@login_required
def feedback_close():
    flat=session["user_id"]
    if int(flat)<100:
        posttime=request.form.get("name")
        now=datetime.datetime.now()
        comment=request.form.get("comment")
        drows=db.execute("SELECT * FROM residents WHERE flat= :flat", flat=flat)
        closer=drows[0]["name"]
        db.execute("UPDATE feedback SET status = :status, closer = :closer, closetime = :closetime, comment = :comment WHERE datetime = :datetime", status="Closed", closer=closer, closetime=now, comment=comment, datetime=posttime)
        rows = db.execute("SELECT * FROM feedback ORDER BY datetime DESC")
        return render_template("feedback_book_admin.html", rows=rows)
    else:
        return render_template("feedback.html")

#Feedback ends

#Notices start
@app.route("/notices", methods=["GET", "POST"])
@login_required
def notices():
    """Manage suggestion book"""
    flat=session["user_id"]

    #Checking if resident posted the comment
    if request.method == "POST" and int(flat)<100:
        now=datetime.datetime.now()
        subject=request.form.get("subject")
        notices=request.form.get("notices")
        drows=db.execute("SELECT * FROM residents WHERE flat= :flat", flat=flat)
        name=drows[0]["name"]
        db.execute("INSERT INTO notices (name, datetime, subject, notice, status) VALUES (?, ?, ?, ?, ?)",
            name, now, subject, notices, 'Valid')
        rows = db.execute("SELECT * FROM notices WHERE status = :status ORDER BY datetime DESC", status='Valid')
        return render_template("notices_book_admin.html", rows=rows)

    elif request.method == "GET" and int(flat)<100:
        rows = db.execute("SELECT * FROM notices ORDER BY datetime DESC")
        return render_template("notices_book_admin.html", rows=rows)


    else:
        rows = db.execute("SELECT * FROM notices WHERE status = :status", status='Valid')
        return render_template("notices_book.html", rows=rows)

@app.route("/notices_todo", methods=["GET", "POST"])
@login_required
def notices_todo():
    """Manage suggestion book"""
    return render_template("notices.html")

@app.route("/notices_more", methods=["GET", "POST"])
@login_required
def notices_more():
    """Manage notice board"""
    flat=session["user_id"]
    if request.method == "POST" and int(flat)>100:
        datetime=request.form.get("name")
        rows = db.execute("SELECT * FROM notices WHERE datetime = :datetime ORDER BY datetime DESC", datetime=datetime)
        return render_template("notices_more.html", rows=rows, name=datetime)

    elif request.method == "POST" and int(flat)<100:
        datetime=request.form.get("name")
        rows = db.execute("SELECT * FROM notices WHERE datetime = :datetime ORDER BY datetime DESC", datetime=datetime)
        return render_template("notices_more_admin.html", rows=rows)
    else:
        return render_template("notices.html")

@app.route("/notices_close", methods=["GET", "POST"])
@login_required
def notices_close():
    flat=session["user_id"]
    if int(flat)<100:
        posttime=request.form.get("name")
        now=datetime.datetime.now()
        drows=db.execute("SELECT * FROM residents WHERE flat= :flat", flat=flat)
        closer=drows[0]["name"]
        db.execute("UPDATE notices SET status = :status WHERE datetime = :datetime", status="Withdrawn", datetime=posttime)
        rows = db.execute("SELECT * FROM notices ORDER BY datetime DESC")
        return render_template("notices_book_admin.html", rows=rows)
    else:
        return render_template("notices.html")

#Notices ends

#Maintenance starts
@app.route("/maintenance", methods=["GET", "POST"])
@login_required
def maintenance():
    """Manage maintenance payment"""
    flat=session["user_id"]
    #Checking if resident made the payment
    if request.method == "POST" and int(flat)>100:
        now=datetime.datetime.now()
        month=request.form.get("month")
        year=request.form.get("year")
        amount=request.form.get("amount")
        mode=request.form.get("mode")
        refno=request.form.get("refno")
        drows=db.execute("SELECT * FROM residents WHERE flat= :flat", flat=flat)
        area=drows[0]["area"]
        db.execute("INSERT INTO payment (flat, month, year, amount, status, mode, refno, datetime, area) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            flat, month, year, amount, 'Initiated', mode, refno, now, area)
        rows = db.execute("SELECT * FROM payment WHERE flat = :flat ORDER BY datetime DESC", flat=flat)
        return render_template("maintenance_book.html", rows=rows, inr=inr)

    elif request.method == "GET" and int(flat)<100:
        rows = db.execute("SELECT * FROM payment ORDER BY datetime DESC")
        return render_template("maintenance_book_admin.html", rows=rows, inr=inr)

    else:
        rows = db.execute("SELECT * FROM payment WHERE flat = :flat ORDER BY datetime DESC", flat=flat)
        return render_template("maintenance_book.html", rows=rows, inr=inr)

@app.route("/payment_todo", methods=["GET", "POST"])
@login_required
def paymenttodo():
    """Make a payment"""
    return render_template("maintenance.html")

@app.route("/payment_more", methods=["GET", "POST"])
@login_required
def payment_more():
    """Manage suggestion book"""
    flat=session["user_id"]
    if request.method == "POST" and int(flat)<100:
        datetime=request.form.get("name")
        rows = db.execute("SELECT * FROM payment WHERE datetime = :datetime ORDER BY datetime DESC", datetime=datetime)
        return render_template("maintenance_more_admin.html", rows=rows, inr=inr)
    else:
        return render_template("maintenance.html")


@app.route("/payment_close", methods=["GET", "POST"])
@login_required
def payment_close():
    flat=session["user_id"]
    if int(flat)<100:
        name=request.form.get("name")
        db.execute("UPDATE payment SET status = :status WHERE datetime = :name", status="Paid", name=name)
        rows = db.execute("SELECT * FROM payment ORDER BY datetime DESC")
        return render_template("maintenance_book_admin.html", rows=rows, inr=inr)
    else:
        return render_template("maintenance.html")

#Maintenance ends


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure flat was submitted
        if not request.form.get("flat"):
            return apology("must provide flat no", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for flat
        rows = db.execute("SELECT * FROM residents WHERE flat = :flat",
                          flat=request.form.get("flat"))

        # Ensure flat exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid flat No and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["flat"]

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

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("password"):
            return apology("must enter old password", 403)

        # Ensure new password was submitted
        elif not request.form.get("npassword"):
            return apology("must provide new password", 403)

        # Checking new password length
        if (len(request.form.get("npassword"))<3):
            return apology("Password must be at least of 6 characters", 403)

        # Ensure new password was retyped
        elif not request.form.get("n2password"):
            return apology("must retype password", 403)

        # Ensure new passwords match
        elif not request.form.get("npassword") == request.form.get("n2password"):
            return apology("Passwords don't match", 403)

        # Query database for flat
        rows = db.execute("SELECT * FROM residents WHERE flat = :flat",
                          flat=session["user_id"])

        # Ensure old password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
           return apology("invalid old password", 403)

        # Update password into database
        hash = generate_password_hash(request.form.get("npassword"))
        db.execute("UPDATE residents SET hash = :hash WHERE flat=:flat", hash=hash, flat=session["user_id"])

        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_password.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure flat No was submitted
        if not request.form.get("flat"):
            return apology("must provide flat no", 403)

        # Ensure flat not used before

        # Query database for flat
        rows = db.execute("SELECT * FROM residents WHERE flat = :flat",
                          flat=request.form.get("flat"))

        # Ensure flat exists and password is correct
        if len(rows) != 0:
            return apology("Flat No already registered", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password was retyped
        elif not request.form.get("confirmation"):
            return apology("must retype password", 403)

        # Ensure passwords match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords don't match", 403)

        # Insert password into database
        flat = request.form.get("flat")
        name = request.form.get("name")
        number = request.form.get("number")
        email = request.form.get("email")
        area = request.form.get("area")
        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO residents (flat, name, hash, number, email, area) VALUES (:flat, :name, :hash, :number, :email, :area)", flat=flat, name=name, hash=hash, number=number, email=email, area=area)

        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
