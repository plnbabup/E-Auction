from django.contrib.auth.models import User
from django.db import models
from time import time
from django.utils import timezone
from django.core.validators import RegexValidator

# Create your models here.

class Product(models.Model):
    product_name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='photos/products')
    description = models.TextField(max_length=300, default="")
    minimum_price = models.IntegerField(null=True)
    bid_end_date = models.DateField(default=None)
    is_active = models.BooleanField(default=True)
    final_value = models.IntegerField(blank=True, null=True)
    winner = models.ForeignKey(User, on_delete=models.SET("(deleted)"), blank=True, null=True)
    created = models.DateTimeField(default= timezone.now)
    updated = models.DateTimeField(default= timezone.now)

    def statchange(self):
        highest_bid = Bidder.objects.filter(product_id=self).order_by('-bid_amount').first()
        if highest_bid:
            self.winner = highest_bid.user_name
            self.final_value = highest_bid.bid_amount
        self.is_active = False
        self.save()


class Seller(models.Model):
    created = models.DateTimeField(default= timezone.now)
    updated = models.DateTimeField(default= timezone.now)
    user_name = models.ForeignKey(User, on_delete=models.CASCADE)
    product_id = models.ForeignKey(Product, on_delete=models.CASCADE)




class Bidder(models.Model):
    numeric = RegexValidator(r'^[0-9]*$', 'Only numerics are allowed.')

    created = models.DateTimeField(default= timezone.now)
    updated = models.DateTimeField(default= timezone.now)
    user_name = models.ForeignKey(User, on_delete=models.CASCADE)
    product_id = models.ForeignKey(Product, on_delete=models.CASCADE)
    bid_amount = models.CharField(max_length=255, validators=[numeric])

