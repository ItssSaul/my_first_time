from django.db import models
import re
# Create your models here.

class UserManager(models.Manager):
    def reg_validator(self,postData):
        print("here2")
        errors = {}
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9. +_-]+@[a-zA-Z0-9. +_-]+\.[a-zA-Z]+$')
        if len(postData['first_name']) < 3:
            errors['first_name'] = "First Name must be at least 3 characters."
        if len(postData['last_name']) < 3:
            errors['last_name'] = "Lirst Name must be at least 3 characters."
        if not EMAIL_REGEX.match(postData['email']):
            errors['email'] = "Invalid Email."
        if len(postData['password']) < 8 :
            errors['password'] = "Password must be at least 8 characters"
        if postData['password'] != postData['confirm']:
            errors['confirm'] = "Passwords don't match!"
        return errors 

    def login_validator(self,postData):
        errors={}
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9. +_-]+@[a-zA-Z0-9. +_-]+\.[a-zA-Z]+$')
        if not EMAIL_REGEX.match(postData['login_email']):
            errors['login'] = "Invalid Email/Password."
        if len(postData['login_password']) < 8 :
            errors['login'] = "Invalid Email/Password."
        return errors

    def edit_validator(self,postData):
        errors={}
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9. +_-]+@[a-zA-Z0-9. +_-]+\.[a-zA-Z]+$')
        if not EMAIL_REGEX.match(postData['edit_email']):
            errors['edit_email'] = "Invalid Email/Password"
        if len(postData['edit_first_name']) < 3:
            errors['edit_first_name'] = "First Name must be at least 3 characters."
        if len(postData['edit_last_name']) < 3:
            errors['edit_last_name'] = "Lirst Name must be at least 3 characters."
        return errors




class User(models.Model):
    first_name = models.CharField(max_length = 45)
    last_name = models.CharField(max_length = 45)
    email = models.CharField(max_length = 45)
    password = models.CharField(max_length = 45)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class QuoteManager(models.Manager):
    def quote_validator(self,postData):
        errors={}
        if len(postData['author']) < 3:
            errors['author'] = "Author name must be at least 3 characters"
        if len(postData['quote']) == 0:
            errors ['quote'] = "quote must be required"
        return errors


class Create_Quotes(models.Model):
    author=models.CharField(max_length=45)
    quote=models.CharField(max_length=244)
    user=models.ForeignKey(User,related_name="create_quote",on_delete =models.CASCADE)
    likes=models.ManyToManyField(User,related_name="liked_by")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = QuoteManager()
