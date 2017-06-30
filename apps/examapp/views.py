
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

        check = User.objects.login(form_data)

        if type(check) == type(User()):
            request.session['user_id'] = check.id
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
        current_user = getCurrentUser(request)

        friends = User.objects.filter(friends=current_user)
        nonfriends = User.objects.all().exclude(
            friends=current_user).exclude(id=current_user.id)

        print '*' * 25
        print friends
        print '*' * 25

        context = {
            "user": current_user,
            "nonfriends": nonfriends,
            "friends": friends
        }
    return render(request, 'exam/friends.html', context)  # add context here


def getCurrentUser(request):
    user_id = request.session['user_id']
    return User.objects.get(id=user_id)


def addFriend(request, id):

    current_user = getCurrentUser(request)
    user = User.objects.get(id=id)
    user.friends.add(current_user)

    return redirect('/friends')


def removeFriend(request, id):
    current_user = getCurrentUser(request)
    user = User.objects.get(id=id)

    current_user.friends.remove(user)

    return redirect('/friends')


def selectFriend(request, id):
    user = User.objects.get(id=id)
    context = {
        "user": user,
    }

    return render(request, 'exam/user.html', context)
