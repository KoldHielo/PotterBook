from django.db import models
from django.contrib.auth import get_user_model

# Create your models here.




class CustomBusinessUser(models.Model):
  def dynamic_upload(instance, filename):
    return f'businesses/{instance.id}/{filename}'
    
  user = models.OneToOneField(to=get_user_model(), on_delete=models.CASCADE)
  business_name = models.CharField(max_length=200)
  business_bio = models.TextField(max_length=1350, blank=True, null=True)
  services = models.ManyToManyField('main.Service', blank=True)
  photo = models.ImageField(blank=True, null=True, upload_to=dynamic_upload)
  qr_code = models.ImageField(blank=True, null=True, upload_to=dynamic_upload)
  business_slug = models.SlugField(blank=True, null=True)
  stripe_id = models.CharField(max_length=200, blank=True, null=True)
  pref_tz = models.CharField(max_length=255, default='UTC')
  password_reset_date = models.DateTimeField(blank=True, null=True)
  password_reset_code = models.TextField(blank=True, null=True)
  business_accept = models.BooleanField(default=False, blank=True, null=True, verbose_name='Business accepted terms and conditions and privacy policy')

  def __str__(self):
    return self.business_slug

class Service(models.Model):
  business = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
  service = models.CharField(max_length=200)
  price = models.IntegerField()
  currency = models.CharField(max_length=50)
  

  def __str__(self):
    business = business = CustomBusinessUser.objects.get(user=self.business).business_slug
    return f'{business} - {self.service}'

class Appointment(models.Model):
  business = models.ForeignKey(to=get_user_model(), on_delete=models.CASCADE, related_name='business')
  slot = models.DateTimeField()
  address = models.TextField(blank=True, null=True)
  telephone = models.CharField(max_length=50, blank=True, null=True)
  note = models.TextField(blank=True, null=True)
  is_booked = models.BooleanField(default=False)
  stripe_id = models.CharField(max_length=255, null=True, blank=True)
  charge_id = models.CharField(max_length=255, null=True, blank=True)
  refunded = models.BooleanField(default=False)
  name = models.CharField(max_length=200, blank=True, null=True)
  email = models.EmailField(blank=True, null=True)
  service_reference = models.CharField(max_length=255, blank=True, null=True)
  price_reference = models.IntegerField(blank=True, null=True)
  currency_reference = models.CharField(max_length=50, blank=True, null=True)
  service = models.ForeignKey(Service, on_delete=models.SET_NULL, blank=True, null=True)
  client_accept = models.BooleanField(default=False, blank=True, null=True, verbose_name='Client accepted terms and conditions and privacy policy')
  
  def dynamic_upload(instance, filename):
    return f'businesses/{instance.business.id}/appointments/{filename}'
  verification_code = models.TextField(blank=True, null=True)
  qr_code = models.ImageField(upload_to=dynamic_upload, blank=True, null=True)
  verified = models.BooleanField(default=False)

  def __str__(self):
    business = CustomBusinessUser.objects.get(user=self.business).business_slug
    return f'{"~" if self.is_booked is True else ""}{business} - {self.slot}'
  
  class EmailToken(models.Model):
    token = models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    user  = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)