from django.urls import path
from .views import upload_file, view_files, download_file,create_container,request_file,get_container_name,send_file,approve_request,decrypt_file,requested_files,logout_view
from . import views
urlpatterns = [
    # User authentication
    path('', views.landing_page, name='landing_page'),
    path('logout/', logout_view, name='logout'),
    path('requested-files/', requested_files, name='requested_files'),
    path('profile/', views.view_profile, name='view_profile'),
    path('signup/', views.signup, name="signup"),
    path('login/', views.login_view, name="login"),
    path('dashboard/', views.dashboard_view, name="dashboard"),
    path('get_container_name/', views.get_container_name, name='get_container_name'),
    path('', views.Home, name="Home"),
    path('upload_file/', views.upload_file, name='upload_file'),
    path('view-files/', views.view_files, name='view_files'),
    path('download/<str:file_name>/', views.download_file, name='download_file'),
    path('create-container/', create_container, name='create_container'),
    path('request_file/',request_file, name='request_file'),
    path('approve_request/', approve_request, name='approve_request'),
    path('send_file/', send_file, name='send_file'),
    path('decrypt/<str:filename>/', decrypt_file, name='decrypt_file'),
]