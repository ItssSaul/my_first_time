from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('register',views.register),
    path('dashboard',views.dashboard),
    path('login',views.login),
    path('logout',views.logout),
    path('addquotes',views.addquotes),
    path('destroy_quote/<int:quote_id>',views.destroy_quote),
    path('edit_user',views.edit_user),
    path('update_user',views.update_user),
    path('show_user/<int:user_id>',views.show_user),
    path('like/<int:every_quote_id>/<int:user_id>',views.like),
]

