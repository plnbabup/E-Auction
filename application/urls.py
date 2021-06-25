from django.urls import path
from django.conf.urls import url
from application import views
from django.conf.urls import url, include
from django.contrib import admin
from .views import BidderListView, ProductDelete
from .views import ProductDetailView, AddProductView, ProductView
from django.contrib.auth.decorators import login_required
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.auth.views import logout_then_login

urlpatterns = [

     path('', views.home, name="home"),
     path('login/',views.login,name="login"),
     path('session/',views.session,name="seslog"),
     path('logout/', views.logout, name='logout'),
     path('aboutus/',views.aboutus,name="aboutus"),
     path('mybids/', views.my_bid, name="my_bids"),
     path('myauctions/', views.my_auction, name="my_auctions"),
     path('viewproduct/', views.ProductView, name="view_product"),
     path('registration/',views.registration,name="registration"),
     path('change_password/',views.change_pswd,name="change_pswd"),
     path('activate/<uidb64>/<token>/',views.activate,name='activate'),
     path('resetPassword/', views.resetPassword, name='resetPassword'),
     path('save_bid/', login_required(views.save_bid), name="save_bid"),
     path('forgotPassword/', views.forgotPassword, name='forgotPassword'),
     path('addproduct/', login_required(AddProductView.as_view()), name="add_product"),
     path('resetpassword_validate/<uidb64>/<token>/', views.resetpassword_validate, name='resetpassword_validate'),
     url(r'^productdetails/(?P<pk>[0-9]+)$', login_required(ProductDetailView.as_view()), name="product_detail"),
     url(r'^deleteproduct/(?P<pk>[0-9]+)$', login_required(ProductDelete.as_view()), name="delete_product"),
     url(r'^bidderlist/(?P<pk>[0-9]+)$', login_required(BidderListView.as_view()), name="bidder_list"),   

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


