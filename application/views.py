import datetime

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User,auth

from django.http import HttpResponse,HttpResponseRedirect
from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render,redirect
from django.contrib import messages
from django.template import loader

from .models import Product, Bidder, Seller
from django.db.models import Max
from django.conf.urls import url
from django.urls import reverse

#Views
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView
from django.views.generic.edit import DeleteView
from django.views.generic import ListView

# Verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
#---------------------------------------------------Create your views here-------------------------------------------------------------------------------------------------

def home(request):
    send_email()
    return render(request, 'home.html')

def aboutus(request):
    return render(request, 'about.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    return redirect('/')

#-----------------------------------------------------------Login---------------------------------------------------------------------------------------------------------

def login(request):
    if request.method=='POST':
        username=request.POST.get('username')
        password=request.POST.get('password')

        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request,user)
            return render(request, 'home.html')
            
        else:
            messages.info(request,'Invalid Credentials')
            return render(request,'login.html')

    else:
        return render(request,'login.html')

#-----------------------------------------------------------Session---------------------------------------------------------------------------------------------------------

def session(request):
    if request.method=='POST':
        username=request.POST.get('username')
        password=request.POST.get('password')

        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request,user)
            return render(request, 'home.html')
            
        else:
            messages.info(request,'Invalid Credentials')
            return render(request,'logses.html')

    else:
        return render(request,'logses.html')

#-----------------------------------------------------------Registration---------------------------------------------------------------------------------------------------------

def registration(request):
    if request.method=='POST':
        first_name = request.POST.get('fname')
        last_name = request.POST.get('lname')
        username=request.POST.get('username')
        email=request.POST.get('email')
        password1=request.POST.get('password1')
        password2=request.POST.get('password2')
        
        if password1==password2:
            if User.objects.filter(username=username).exists():
                messages.info(request,'User Name Is Alraedy Taken')
                return redirect('/registration')

            elif User.objects.filter(email=email).exists():
                messages.info(request,'Email ID Is Alraedy Taken')
                return redirect('/registration')
                
            else:
                user =User.objects.create_user(first_name=first_name, last_name=last_name,username=username,email=email,password=password1)
                user.is_active=False
                user.save()
                current_site = get_current_site(request)
                mail_subject = 'Please activate your account'
                message = render_to_string('account_verification_email.html', {
                    'user': user,
                    'domain': current_site,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
                to_email = email
                send_email = EmailMessage(mail_subject, message, to=[to_email])
                send_email.send()
                return redirect('/login/?command=verification&email='+email)
                
        else:
            messages.info(request,'Password Not Match')
            return render(request,'registration.html')

    else:
        return render(request,'registration.html')

#-----------------------------------------------------------SaveBid---------------------------------------------------------------------------------------------------------

@login_required(login_url='login')
def save_bid(request):
    context = dict()
    context['product_list'] = Product.objects.get(id=request.POST.get('product_id'))
    context['seller'] = Seller.objects.get(product_id_id=request.POST.get('product_id'))
    if request.method == 'POST':
        if int(request.POST.get('minimum_price')) > int(request.POST.get('bid_amount')):
            context['error'] = "Bid price should be more than minimum price"
            return render(request, 'product_detail.html', context)
        else:
            x = Bidder.objects.filter(product_id=Product.objects.get(id=request.POST.get('product_id'))).values('user_name')
            a = 0
            for item in x:
                if item['user_name'] == request.user.id:
                    y = Bidder.objects.get(user_name=request.user.id, product_id=Product.objects.get(id=request.POST.get('product_id')))
                    y.bid_amount = int(request.POST.get('bid_amount'))
                    y.save()
                    a = 1
            if not a:
                obj = Bidder(user_name=request.user, product_id=Product.objects.get(id=request.POST.get('product_id')), bid_amount=int(request.POST.get('bid_amount')))
                obj.save()
            return HttpResponseRedirect(reverse('view_product'))
    return render(request, 'product_detail.html', context)

#-----------------------------------------------------------Product View---------------------------------------------------------------------------------------------------------

@login_required(login_url='login')
def ProductView(request):
    send_email()
    product_list = Product.objects.all()
    latest_auction_list = product_list.filter(is_active=True).order_by('bid_end_date')
    paginator = Paginator(latest_auction_list, 3)
    page = request.GET.get('page')
    paged_products = paginator.get_page(page)
    template = loader.get_template('product_list.html')
    context = {
        'title': "Active auctions",
        'product_list': paged_products,
    }
    return HttpResponse(template.render(context, request))

#-----------------------------------------------------------Add Product View---------------------------------------------------------------------------------------------------------

class AddProductView(CreateView):
    model = Product
    fields = ["product_name", "minimum_price", "bid_end_date", "image", "description"]
    template_name = 'product_form.html'

    def form_valid(self, form):
        obj = Seller(user_name = self.request.user, product_id = form.save())
        obj.save()
        return super(AddProductView, self).form_valid(form)

    def get_success_url(self):
        return reverse('view_product')

#-----------------------------------------------------------Product Detail View---------------------------------------------------------------------------------------------------------

class ProductDetailView(DetailView):
    model = Product
    context_object_name = 'product_list'
    template_name = 'product_detail.html'

    def get_context_data(self, **kwargs):
        context = super(ProductDetailView, self).get_context_data(**kwargs)
        x = Seller.objects.all()
        context["seller"] = Seller.objects.get(product_id_id=self.kwargs['pk'])
        return context

#-----------------------------------------------------------Product Delete---------------------------------------------------------------------------------------------------------

class ProductDelete(DeleteView):
    model = Product
    template_name = 'product_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super(ProductDelete, self).get_context_data(**kwargs)
        context["product_id"] = self.kwargs['pk']
        return context
    def get_success_url(self):
        return reverse('view_product')

#-----------------------------------------------------------Bidder List View---------------------------------------------------------------------------------------------------------

class BidderListView(ListView):
    model = Bidder
    template_name = 'bidder_list.html'

    def get_queryset(self):
        return Bidder.objects.filter(product_id=self.kwargs['pk'])

    def get_context_data(self, **kwargs):
        context = super(BidderListView, self).get_context_data(**kwargs)
        context["product_id"] = self.kwargs['pk']
        return context

#-----------------------------------------------------------My Bids---------------------------------------------------------------------------------------------------------

@login_required(login_url='login')
def my_bid(request):
    bid_list = Bidder.objects.all().filter(user_name=request.user).order_by('-created')
    send_email()

    template = loader.get_template('my_bids.html')
    context = {
        'my_bids_list': bid_list,
    }
    return HttpResponse(template.render(context, request))

#-----------------------------------------------------------My Auctions---------------------------------------------------------------------------------------------------------

@login_required(login_url='login')
def my_auction(request):
    bid_list = Seller.objects.all().filter(user_name=request.user).order_by('-created')
    send_email()

    template = loader.get_template('my_auctions.html')
    context = {
        'my_bids_list': bid_list,
    }
    return HttpResponse(template.render(context, request))

#-----------------------------------------------------------Change Password---------------------------------------------------------------------------------------------------------

@login_required(login_url='login')
def change_pswd(request):
    if request.method=='POST':
        old_pswd = request.POST.get('old_pswd')
        new_pswd = request.POST.get('new_pswd')
        con_pswd = request.POST.get('con_pswd')

        user = User.objects.get(username__exact=request.user.username)
        if new_pswd == con_pswd:
            success = user.check_password(old_pswd)
            if success:
                user.set_password(new_pswd)
                user.save()
                messages.success(request, 'Password updated successfully')
                auth.logout(request)
                return redirect('/login/')
            else:
                messages.error(request, 'Enter valid old password')
                return render(request, 'change_pswd.html')
        else:
            messages.error(request, 'Confirm password does not match with new password')
            return render(request, 'change_pswd.html')
    else:
        return render(request, 'change_pswd.html')

#-----------------------------------------------------------Mailing---------------------------------------------------------------------------------------------------------

def mailing(bidder, seller, name):
    if (bidder == 0):
        mail_subject = 'Auction ENDED'
        message = render_to_string('no_bidder.html', {
            'sale':seller[0]['first_name'],
            'name':name,
        })
        to_email = seller[0]['email']
        send_email = EmailMessage(mail_subject, message, to=[to_email])
        send_email.send()
    else:
        mail_subject = 'Auction ENDED. You WON!!'
        message = render_to_string('won_bidder.html', {
            'sale':seller[0]['first_name'],
            'buy':bidder[0]['first_name'],
            'mail':seller[0]['email'],
            'name':name,
        })
        to_email = bidder[0]['email']
        send_email = EmailMessage(mail_subject, message, to=[to_email])
        send_email.send()

        mail_subject = 'Auction ENDED. Your product was sold!!'
        message = render_to_string('won_seller.html', {
            'sale':seller[0]['first_name'],
            'buy':bidder[0]['first_name'],
            'mail':bidder[0]['email'],
            'name':name
        })
        to_email = seller[0]['email']
        send_email = EmailMessage(mail_subject, message, to=[to_email])
        send_email.send()
        

        if(len(bidder)>1):
            for b in bidder[1:]:
                mail_subject = 'Auction ENDED. Explore more!!'
                message = render_to_string('lost_bidder.html', {
                    'buy':b['first_name'],
                    'name':name,
                })
                to_email = b['email']
                send_email = EmailMessage(mail_subject, message, to=[to_email])
                send_email.send()

#-----------------------------------------------------------Send Mail---------------------------------------------------------------------------------------------------------

def send_email():
    product = Product.objects.all()
    for item in product:
        if((item.bid_end_date < datetime.date.today()) and (item.is_active)):
            item.statchange()
            name = item.product_name
            bidder = User.objects.filter(bidder__product_id=item.id).annotate(max = Max('bidder__bid_amount')).values('first_name','email').order_by('-max')
            seller = User.objects.filter(seller__product_id=item.id).values('first_name','email')
            if(bidder):
                mailing(bidder, seller, name)
            else:
                mailing(0, seller, name)          

#-----------------------------------------------------------Activate---------------------------------------------------------------------------------------------------------

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account is activated.')
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('registration')

#-----------------------------------------------------------Forgot Password---------------------------------------------------------------------------------------------------------

def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)

            # Reset password email
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            message = render_to_string('reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(request, 'Password reset email has been sent to your email address.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist!')
            return redirect('forgotPassword')
    return render(request, 'forgotPassword.html')

#-----------------------------------------------------------Reset password Validation---------------------------------------------------------------------------------------------------------

def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(request, 'This link has been expired!')
        return redirect('login')

#-----------------------------------------------------------Reset Password---------------------------------------------------------------------------------------------------------

def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = User.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Password do not match!')
            return redirect('resetPassword')
    else:
        return render(request, 'resetPassword.html')

