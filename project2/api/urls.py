from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user, name='register_user'),
    path('login/', views.login_user, name='login_user'),
    path('logout/',views.logout_user,name="logout_user"),
    path('transfer/', views.make_transfer, name='make_transfer'),
    path('transactions/', views.show_transactions, name='show_transactions'),
    path('users/', views.show_users, name='show_users'),
    path('accounts/', views.show_accounts, name='show_accounts'),
]