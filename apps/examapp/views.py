
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
            alias=form_data['alias'],
            email=form_data['email'],
            dob=form_data['dob'],
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
        return redirect('/friends')

    return redirect('/')

#
#  logout function
#


def logout(request):
    request.session.pop('user_id')  # pop the value in the session variable

    return redirect('/')  # send you back to the index page


#
#  Query results of the website
#


def friends(request):
    if "user_id" in request.session:
        print '*' * 25
        print request.session['user_id']
        # user_id = request.session['user_id']
        # current_user = User.objects.get(id=user_id)
        current_user = getCurrentUser(request)
        print current_user

        nonfriends = User.objects.filter(
            friends__isnull=True)  # Query the non friends
        friends = User.objects.filter(
            friends__isnull=False)  # Query the friends

        context = {
            "user": current_user,
            "nonfriends": nonfriends,
            "friends": friends,
            #         "trips" = Trips.orderby('start-date')
        }
    return render(request, 'exam/friends.html', context)  # add context here


def getCurrentUser(request):
    if request.method == "POST":
        user_id = request.session['user_id']
        return User.objects.get(id=user_id)


def addFriend(request, id):
    if request.method == "POST":
        current_user = getCurrentUser(request)
        user = User.objects.get(id=id)

        current_user.friend.add(user)

    return redirect('/friends')


def removeFriend(request, id):
    if request.method == "POST":
        current_user = getCurrentUser(request)
        user = User.objects.get(id=id)

        current_user.friend.remove(user)

    return redirect('/friends')


def selectFriend(request, id):
    if request.method == "POST":
        friend = User.objects.filter(id=id)

        context = {
            "friend": friend,
        }

    return render(request, 'user.html', context)
