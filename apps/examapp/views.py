
from __future__ import unicode_literals
import bcrypt
from django.shortcuts import render, redirect, HttpResponse, reverse
from .models import *
from django.contrib import messages
# messages.success(request, "Sucessful Registation")
# messages.error(request, "User is not in the Database")

# function to print error messages for registration to display on Registration page


def error_flash(request, errors):
    for error in errors:
        messages.error(request, error)


def index(request):
    # print inside the terminal to check anything happening here
    print 'Inside the the index method'
    return render(request, 'exam/index.html')

#
#  Creat new user  function
#


def create(request):
    print 'Inside the the CREATE method'
    if request.method == "POST":
        form_data = request.POST
        check = User.objects.validate(form_data)

        if check != []:
            error_flash(request, check)
            return redirect('/')
        # valid form data
        password = str(form_data['password'])  # convert password to string
        hashed_pw = bcrypt.hashpw(
            password, bcrypt.gensalt())  # hash the password

        user = User.objects.create(
            name=form_data['name'],
            username=form_data['username'],
            email=form_data['email'],
            password=hashed_pw

        )  # saving feilds to the database including hashed password.

        request.session['user_id'] = user.id
        messages.success(request, "Sucessful Registration")
        return redirect('/')

#
#  login and validate function
#


def login(request):
    print "Inside the login method."

    if request.method == "POST":
        form_data = request.POST

        check = User.objects.validate_login(form_data)

        if check:
            print check
            error_flash(request, check)

            return redirect('/')

        User.objects.login(form_data)
        return redirect('/dashboard')

    return redirect('/')

#
#  logout function
#


def logout(request):
    request.session.pop('user_id')  # pop the value in the session variable

    return redirect('/')  # send you back to the index page

#
#  ADD function
#


def add(request):
    print 'Inside the the ADD method'
    if request.method == "POST":
        form_data = request.POST

        check = ADD.objects.validate_login(
            form_data)  # calls vaidate method

        if check != []:
            error_flash(request, check)
            return redirect('/')

            ADD = User.objects.create(
                # name=form_data['name'],
                # username=form_data['username'],
                # email=form_data['email'],
                # password=hashed_pw

            )  # saving feilds to the database including hashed password.
    messages.success(request, "Sucessfully added record")
    return render(request, 'exam/add.html')

#
#  Query results of the website
#


def result(request):

    return render(request, 'exam/result.html')

#
#  Query results of the website
#


def dashboard(request):
    if "user_id" in request.session:
        print '*' * 25
        print request.session['user_id']
        user_id = request.session['user_id']
        current_user = User.objects.get(id=user_id)
        print current_user

    #     trips = Trip.objects.all()

        context = {
            "user": current_user
            #         "trips" = Trips.orderby('start-date')
        }
    return render(request, 'exam/dashboard.html', context)  # add context here


def get_current_user(request):
    user_id = request.session['user_id']
    return User.objects.get(id=user_id)
