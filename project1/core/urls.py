from django.urls import path
from . import views
urlpatterns = [
    #API Endpoints
    path('api/register/', views.register_user, name='register_user'),
    path('api/login/', views.login_user, name='login_user'),
    path('api/logout/', views.logout_user, name='logout_user'),
    path('api/transfer/', views.make_transfer, name='make_transfer'),
    path('api/transactions/', views.get_transactions_api, name='get_transactions_api'),
    
    # Template Endpoints
    path('register/',views.register_page, name="register_page"),
    path('home/',views.home_page,name="home_page"),
    path('login/',views.login_page, name="login_page"),
    path('transfer/',views.transfer_page, name="transfer_page"),
    path('transactions/',views.transaction_page,name='transaction_page'),
    path('profile/',views.user_profile,name="user_profile")

]