from django.shortcuts import render, redirect
from django.http import JsonResponse, Http404
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.core.mail import send_mail
from django.urls import reverse
from django.core.files.images import ImageFile
import re
from django.contrib.auth.models import User
from .models import CustomBusinessUser, Appointment, Service
import os
import io
import stripe
import qrcode
from PIL import Image
from datetime import datetime, timedelta
from django.utils import timezone
import json
from django.utils.text import slugify
from django.db.models import Model, Sum
import secrets
from django.core.paginator import Paginator
from hashlib import sha256
import pytz


company = 'PotterBook'
stripe.api_key = os.environ['STRIPE_SK']
reg_subdoms = {'www', 'potterbook'}

def convert_tz(dtObj, tz_string):
  tz = pytz.timezone(tz_string)
  converted_dt = dtObj.astimezone(tz)
  return converted_dt

def assert_tz(dtObj, tz_string):
  tz = pytz.timezone(tz_string)
  asserted_tz = tz.localize(dtObj)
  return asserted_tz

def hash_value(value):
  salt = os.environ['SALT']
  pepper = os.environ['PEPPER']
  data = salt + value + pepper
  hash = sha256(data.encode()).hexdigest()
  return hash
  

def get_stripe_user(user):
  try:
    custom_user = CustomBusinessUser.objects.get(user=user)
    if custom_user.stripe_id is None:
      return None
    else:
      stripe_user = stripe.Account.retrieve(custom_user.stripe_id)
      if stripe_user['charges_enabled']:
        return stripe_user
      else:
        return None
  except:
    return None

def validate_email(email: str):
  if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
    return True
  else:
    return False

def validate_post_data(post_data: dict):
  for key, value in post_data.items():
    if re.match(r'^\s*$', value):
      return False
  return True

def validate_passwords(password: str, password_confirm: str):
  if password != password_confirm:
    return 'no match'
  elif re.match(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password) is None:
    return 'incorrect format'
  else:
    return True

def trim(string: str):
  return ' '.join(string.split())

def generate_unique_slug(model: Model, model_instance, value: str, slug_field: str):
  slug = slugify(value)
  unique_slug = slug
  num = 1
  query_set = model.objects.filter(**{slug_field: unique_slug})
  query_set = query_set.exclude(id=model_instance.id)
  while query_set.exists():
    unique_slug = f"{slug}-{num}"
    num += 1
    query_set = model.objects.filter(**{slug_field: unique_slug})
    query_set = query_set.exclude(id=model_instance.id)
  return unique_slug

def generate_qr_code(data, filename, format):
  qr = qrcode.QRCode(version=1, box_size=40, border=4)
  qr.add_data(data)
  qr.make(fit=True)
  img = qr.make_image(fill="black", back_color="white")
  image_buffer = io.BytesIO()
  img.save(image_buffer, format=format.upper())
  image_buffer.seek(0)
  image_file = ImageFile(image_buffer, name=f'{filename}.{format.lower()}')
  return image_file

def appointment_available(request, slug):
  if request.method == 'POST':
    try:
      service_string = request.POST['service']
      iso = request.POST['iso']
      date = datetime.fromisoformat(iso)
      business = CustomBusinessUser.objects.get(
        business_slug=slug
      )
      service = Service.objects.get(
        business=business.user,
        service=service_string
      )
    except:
      warning = 'invalid POST request data. Please try again'
      return JsonResponse({'warning', warning})
    appointment = Appointment.objects.filter(
      business=business.user,
      slot=date,
      service=service,
      is_booked=False
    )
    if appointment.exists():
      return JsonResponse({'available': True})
    else:
      return JsonResponse({'available': False})
    

#Stripe Connect & Disconnect
def profile(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated is False:
    warning = 'You must be logged in to access this page'
    return render(request, 'home/home.html', {'warning': warning})
  user_profile = CustomBusinessUser.objects.get(user=request.user)
  services = Service.objects.filter(business=request.user)
  stripe_user = get_stripe_user(request.user)
  auth_url = stripe.OAuth.authorize_url(
    client_id=os.environ['STRIPE_CONNECT_ID'],
    scope='read_write',
    redirect_uri=request.build_absolute_uri(reverse('connect'))
  ) if stripe_user is None else None
  context = {
    'auth_url': auth_url,
    'stripe_linked': bool(stripe_user),
    'user_photo': user_profile.photo.url if bool(user_profile.photo) else False,
    'business_name': user_profile.business_name,
    'business_bio': user_profile.business_bio,
    'business_bio_length': user_profile._meta.get_field('business_bio').max_length,
    'business_slug': user_profile.business_slug,
    'pref_tz': user_profile.pref_tz,    'business_qr': user_profile.qr_code.url if bool(user_profile.qr_code) else False,
    'business_url': f'https://{user_profile.business_slug}.potterbook.co/',
    'business_services': [[i, slugify(i.service), f'{str(i.price)[0:-2]}.{str(i.price)[-2:]}'] for i in services]
  }
  return render(request, 'profile/profile.html', context=context)

def update_profile(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated:
    if request.method == 'POST' and validate_post_data(request.POST):
      updated = {
        'photo': None,
        'business_name': None,
        'business_url': None,
        'business_bio': None,
        'business_qr': None,
        'service_added': None,
        'service_deleted': None,
        'service_edited': None,
        'pref_tz': None
      }
      try:
        user_profile = CustomBusinessUser.objects.get(
          user=request.user
        )
        pref_tz = request.POST['tz-pref']
        if pref_tz in pytz.all_timezones:
          user_profile.pref_tz = pref_tz
          user_profile.save()
          updated['pref_tz'] = pref_tz
      except:
        pass
          

      try:
        new_photo = request.FILES['new-profile-photo']
        image = Image.open(new_photo)
        image.verify()
        user_profile = CustomBusinessUser.objects.get(user=request.user)
        if bool(user_profile.photo) is True:
          user_profile.photo.delete()
        user_profile.photo = new_photo
        user_profile.save()
        updated['photo'] = user_profile.photo.url
      except:
        pass

      try:
        business_name = trim(request.POST['business_name'])
        user_profile = CustomBusinessUser.objects.get(user=request.user)
        user_profile.business_name = business_name
        slug = generate_unique_slug(CustomBusinessUser, user_profile, user_profile.business_name, 'business_slug')
        user_profile.business_slug = slug
        qr_img = generate_qr_code(f'https://{slug}.potterbook.co/', f'{slug}-qr', 'png')
        user_profile.qr_code.delete()
        user_profile.qr_code = qr_img
        user_profile.save()
        updated['business_name'] = user_profile.business_name
        updated['business_qr'] = user_profile.qr_code.url
        updated['business_url'] = f'https://{user_profile.business_slug}.potterbook.co/'
      except:
        pass

      try:
        business_bio = request.POST['business-bio']
        length_check = len(business_bio.replace('\r', ''))
        user_profile = CustomBusinessUser.objects.get(user=request.user)
        bio_maxlength = user_profile._meta.get_field('business_bio').max_length
        if length_check <= bio_maxlength:
          user_profile.business_bio = business_bio
          user_profile.save()
          updated['business_bio'] = user_profile.business_bio
      except:
        pass

      try:
        service_name = trim(request.POST['service-name'])
        service_regex = r'^[a-zA-Z0-9\s]+$'
        pounds = trim(request.POST['pounds'])
        pence = trim(request.POST['pence'])
        service_check = Service.objects.filter(business=request.user, service=service_name)
        if not re.match(service_regex, service_name):
          raise Exception('Service name not formatted correctly. Only words, numbers and whitespace allowed.')
        if len(pounds) < 1 or len(pence) != 2:
          raise Exception('Service Form data not formatted correctly')
        if int(pounds) >= 5 and int(pence) in range(0, 100):
          price = int(pounds + pence)
          if service_check.exists() is False:
            service = Service.objects.create(
              business=request.user,
              service=service_name,
              price=price,
              currency='gbp'
            )
            updated['service_added'] = {
              'service_name': service.service,
              'price': service.price,
              'currency': service.currency,
              'service_slug': slugify(service.service)
            }
          else:
            updated['service_added'] = 'already_exists'
      except:
        pass

      try:
        service_to_delete = request.POST['delete_service']
        check_service_to_delete = Service.objects.filter(business=request.user, service=service_to_delete)
        if check_service_to_delete.exists():
          associated_appointments = Appointment.objects.filter(
            business=request.user,
            service=check_service_to_delete.first(),
            is_booked=False
          )
          associated_appointments.delete()
          check_service_to_delete.delete()
          updated['service_deleted'] = service_to_delete
        else:
          updated['service_deleted'] = 'does_not_exist'
      except:
        pass

      try:
        service_regex = r'^[a-zA-Z0-9\s]+$'
        check_service_name = trim(request.POST['check_service_name'])
        check_service_price = trim(request.POST['check_service_price'])
        new_service_name = trim(request.POST['new_service_name'])
        new_service_price = trim(request.POST['new_service_price'])

        if not re.match(service_regex, new_service_name):
          raise Exception('Service name not formatted correctly. Only words, numbers and whitespace allowed.')
        if int(new_service_price) < 500:
          raise Exception('Service price must be £5.00 or more')

        service_data = Service.objects.get(
          business=request.user,
          service=check_service_name,
          price=check_service_price,
          currency='gbp'
        )
        service_data.service = new_service_name
        service_data.price = int(new_service_price)
        service_data.save()
        updated['service_edited'] = {
          'service_name': new_service_name,
          'service_price': new_service_price,
          'old_service_slug': slugify(check_service_name),
          'new_service_slug': slugify(new_service_name),
        }
        
      except Exception as e:
        pass
      return JsonResponse(updated)

def connect(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated:
    user_profile = CustomBusinessUser.objects.get(user=request.user)
    code = request.GET.get('code')
    response = stripe.OAuth.token(
      grant_type='authorization_code',
      code=code
    )
    user_profile.stripe_id = response['stripe_user_id']
    user_profile.save()
    return redirect('profile')

def disconnect(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated:
    try:
      user_profile = CustomBusinessUser.objects.get(user=request.user)
      stripe_id = user_profile.stripe_id
      if stripe_id is not None:
        user_profile.stripe_id = None
        user_profile.save()
        return redirect('profile')
      else:
        return JsonResponse({'warning': 'No Stripe account currently linked in order to disconnect'})
    except Exception as e:
      return JsonResponse({'warning': str(e)})
  else:
    return JsonResponse({'warning': 'You must be logged in to access this page'})
      
# Create your views here.
def home(request):
  context = None
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    try:
      business = CustomBusinessUser.objects.get(business_slug=subdomain)
    except:
      warning = f'Business with slug name "{subdomain}" does not exist.'
      return render(request, 'home/home.html', {'warning': warning})
    slug = subdomain
    stripe_user = get_stripe_user(business.user)
    context = {
      'business_name': business.business_name,
      'business_slug': slug,
      'business_photo': business.photo.url if bool(business.photo) else False,
      'business_bio': business.business_bio if business.business_bio is not None else False,
      'stripe_enabled': bool(stripe_user),
      'business_services': Service.objects.filter(business=business.user)
    }
    if stripe_user is None:
      if business.business_name[-1] == 's':
        possesive_apostrophe = "'"
      else:
        possesive_apostrophe = "'s"
      context['warning'] = f'{business.business_name}{possesive_apostrophe} schedule is not available at the moment. Please check back soon!'
      return render(request, 'business_schedule.html', context)
    else: 
      return render(request, 'business_schedule.html', context)
      
  elif subdomain in reg_subdoms and request.user.is_authenticated:
    context = None
    now = timezone.make_aware(datetime.utcnow())
    
    last_month = now.month - 1
    last_month_year = now.year
    if last_month < 1:
      last_month = 12
      last_month_year -= 1

    next_month = now.month + 1
    next_month_year = now.year
    if next_month > 12:
      next_month = 1
      next_month_year += 1

    month_after_next = next_month + 1
    month_after_next_year = next_month_year
    if month_after_next > 12:
      month_after_next = 1
      month_after_next_year += 1

    last_month_start = timezone.make_aware(
      datetime(
        last_month_year,
        last_month,
        1
      )
    )
    last_month_end = timezone.make_aware(
      datetime(
        now.year,
        now.month,
        1
      ) - timedelta(milliseconds=1)
    )

    next_month_start = timezone.make_aware(
      datetime(
        next_month_year,
        next_month,
        1
      )
    )

    next_month_end = timezone.make_aware(
      datetime(
        month_after_next_year,
        month_after_next,
        1
      ) - timedelta(milliseconds=1)
    )

    this_month_start = timezone.make_aware(
      datetime(
        now.year,
        now.month,
        1
      )
    )

    this_month_end = timezone.make_aware(
      datetime(
        next_month_year,
        next_month,
        1
      ) - timedelta(milliseconds=1)
    )
    
    business = CustomBusinessUser.objects.get(
      user=request.user,
    )
    services = Service.objects.filter(
      business=request.user
    )
    appointments = Appointment.objects.filter(
      business=request.user
    )
    non_refunded_appointments = appointments.filter(
      refunded=False
    )
    booked_appointments = appointments.filter(
      is_booked=True
    )
    unbooked_appointments = appointments.filter(
      is_booked=False
    )
    future_appointments = appointments.filter(
      slot__gte=now
    )
    past_appointments = appointments.filter(
      slot__lt=now
    )
    this_month_appointments = appointments.filter(
      slot__range=(this_month_start, this_month_end)
    )
    last_month_appointments = appointments.filter(
      slot__range=(last_month_start, last_month_end)
    )
    next_month_appointments = appointments.filter(
      slot__range=(next_month_start, next_month_end)
    )
    context = {
      'business': business,
      'services': services,
      
      'appointments': {
        'all': appointments,
        'booked': appointments & booked_appointments,
        'unbooked': appointments & unbooked_appointments,
        'earnings': (booked_appointments & non_refunded_appointments).aggregate(total=Sum('price_reference'))['total'],
        'earnings_this_month': (booked_appointments & this_month_appointments & non_refunded_appointments).aggregate(total=Sum('price_reference'))['total'],
        'all_this_month': this_month_appointments,
        'booked_this_month': this_month_appointments & booked_appointments,
        'unbooked_this_month': this_month_appointments & unbooked_appointments
      },
      'future_appointments': {
        'all': future_appointments,
        'booked': future_appointments & booked_appointments,
        'unbooked': future_appointments & unbooked_appointments,
        'earnings': (booked_appointments & future_appointments & non_refunded_appointments).aggregate(total=Sum('price_reference'))['total'],
        'earnings_next_month': (booked_appointments & next_month_appointments & non_refunded_appointments).aggregate(total=Sum('price_reference'))['total'],
        'all_next_month': next_month_appointments,
        'booked_next_month': next_month_appointments & booked_appointments,
        'unbooked_next_month': next_month_appointments & unbooked_appointments
      },
      'past_appointments': {
        'all': past_appointments,
        'booked': past_appointments & booked_appointments,
        'unbooked': past_appointments & unbooked_appointments,
        'earnings': (booked_appointments & past_appointments & non_refunded_appointments).aggregate(total=Sum('price_reference'))['total'],
        'earnings_last_month': (booked_appointments & last_month_appointments & non_refunded_appointments).aggregate(total=Sum('price_reference'))['total'],
        'all_last_month': next_month_appointments,
        'booked_last_month': last_month_appointments & booked_appointments,
        'unbooked_last_month': last_month_appointments & unbooked_appointments
      }, 
    }
  return render(request, 'home/home.html', context)

def login_page(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated is False:
    if request.method == 'POST':
      username = request.POST['username']
      password = request.POST['password']
      login_user = authenticate(username=username, password=password)
      if login_user is not None:
        login(request, login_user)
        business = CustomBusinessUser.objects.get(
          user=login_user
        )
        business.password_reset_date = None
        business.password_reset_code = None
        business.save()
        return redirect('home')
      else:
        messages.success(
          request,
          'Username and/or password are incorrect. Please try again.'
        )
        return redirect('login')
    return render(request, 'login.html')
  else:
    messages.success(
      request,
      'You are already logged in'
    )
    return redirect('home')

def logout_click(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated:
    logout(request)
  else:
    messages.success(
      request,
      'You are already logged out'
    )
  return redirect('home')

def register(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated:
    context = {
      'replace_state': reverse('home'),
      'warning': 'Logged in users cannot access this page'
    }
    return render(request, 'home/home.html', context)
  if request.method == 'POST':
    try:
      first_name = trim(request.POST['first-name'])
      last_name = trim(request.POST['last-name'])
      business_name = trim(request.POST['business-name'])
      timezone = request.POST['timezone']
      if timezone not in pytz.all_timezones:
        timezone = 'UTC'
      email = trim(request.POST['email'])
      password = request.POST['password']
      confirm_password = request.POST['confirm-password']
      business_accepts = request.POST['business_accepts']
      if business_accepts != 'accepted':
        raise Exception
    except:
      context = {
      'warning': 'Invalid form submission. Please try again.'
    }
      return render(request, 'register.html', context)
    #Verify that username doesn't exist
    if validate_email(email) == False or validate_post_data(request.POST.copy()) == False:
      context = {
      'warning': 'Invalid form submission. Please try again.'
    }
      return render(request, 'register.html', context)
    
    
    user_exists = get_user_model().objects.filter(username=email).exists()
    if user_exists:
      context = {
      'warning': 'Account with this email already exists. Please try again.'
    }
      return render(request, 'register.html', context)
    password_check = validate_passwords(password, confirm_password)
    if password_check == 'no match':
      context = {
        'warning': 'Your passwords didn\'t match up. Please try again.'
      }
      return render(request, 'register.html', context)
    elif password_check == 'incorrect format':
      context = {
        'warning': 'Your passwords do not meet the specified criteria. Please try again.'
      }
      return render(request, 'register.html', context)
    #If everything checks out on the form, create and save user
    new_user = get_user_model().objects.create_user(
      username=email,
      password=password,
      email=email,
      first_name=first_name,
      last_name=last_name
    )
    user_profile = CustomBusinessUser.objects.create(
      user=new_user,
      business_name=business_name,
      business_accept=True,
      pref_tz=timezone
    )
    slug = generate_unique_slug(CustomBusinessUser, user_profile, user_profile.business_name, 'business_slug')
    user_profile.business_slug = slug
    qr_img = generate_qr_code(f'https://{slug}.potterbook.co/', f'{slug}-qr', 'png')
    user_profile.qr_code = qr_img
    user_profile.save()
    #Email welcome message to user and confirmation link
    subject = f'Welcome to {company}!'
    message = f'Hello there {first_name},\n\nThank you for registering to {company}! We hope that our booking tool will help your business to reach new heights and facilitate the booking process for your clients!\n\nThanks so much,\n\nThe {company} team.'
    html_message = '''<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
        
            @import url('https://fonts.googleapis.com/css2?family=Edu+TAS+Beginner&display=swap');
            
            * {{
                font-family: "Edu TAS Beginner", Arial, Sans-Serif, monospace;
            }}
            
            img:first-of-type {{
                display: block;
                margin: 0 auto;
                width: 300px;
                border-radius: 45%;
            }}
            
            p {{
                width: 80%;
                margin: 30px auto;
            }}
            
            div:nth-of-type(2) {{
                width: 80%;
                margin: 20px auto;
                border: 5px solid;
            }}
        </style>
    </head>
    <body>
        <div>
        <p>Hello there {first_name},</p>
        <p>Thank you for registering to {company}! We hope that our booking tool will help your business to reach new heights and facilitate the booking process for your clients!</p>
        <p>Thanks so much,</p>
        <p>The {company} team.</p>
        </div>
    </body>
</html>'''.format(first_name=first_name, company=company)
    send_mail(
      subject=subject,
      message=message,
      html_message=html_message,
      from_email='info@potterbook.co',
      recipient_list=[email]
    )
    login_user = authenticate(username=email, password=password)
    if login_user is not None:
      login(request, login_user)
      stripe_user = get_stripe_user(new_user)
      auth_url = stripe.OAuth.authorize_url(
    client_id=os.environ['STRIPE_CONNECT_ID'],
    scope='read_write',
    redirect_uri='https://calendar-app.team-oldfield.repl.co/connect/'
  ) if stripe_user is None else None
      context = {
        'auth_url': auth_url,
        'stripe_linked': bool(stripe_user),
        'user_photo': user_profile.photo.url if bool(user_profile.photo) else False,
        'business_name': user_profile.business_name,
        'business_bio': user_profile.business_bio,
        'business_bio_length': user_profile._meta.get_field('business_bio').max_length,
        'business_slug': user_profile.business_slug,
        'business_qr': user_profile.qr_code.url if bool(user_profile.qr_code) else False,
        'business_url': reverse('business_schedule', args=[user_profile.business_slug]),
        'message': 'You have successfully created an account! Please update your profile to get the best experience',
        'replace_state': reverse('profile'),
        'pref_tz': timezone
    }
      return render(request, 'profile/profile.html', context)
    else:
      context = {
      'warning': 'Something went wrong. Please try again.'
    }
      return render(request, 'register.html', context)
  else:
    return render(request, 'register.html')

#Calendar
def edit_availability(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated is False:
    warning = 'You must be logged in to access this page'
    return JsonResponse({'warning': warning})
    
  if request.method == 'POST':
    #Retreive POST data and set time variables
    try:
      action = request.POST['action']
      weekdays = request.POST.getlist('weekdays')
      app_list = []
      times = request.POST.getlist('time')
      quantityDWM = int(request.POST['quantityDaysWeeksMonths'])
      over_period = request.POST['weeksMonthsYears']
      tz_string = request.POST['ee-timezone']
      services = request.POST.getlist('services-for-appointments')

      if len(services) == 1 and services[0] == 'all_services':
        service_list = Service.objects.filter(business=request.user)
      else:
        service_list = [Service.objects.get(business=request.user, service=i) for i in services]
    except:
      warning = 'Invalid form submission.'
      return JsonResponse({'warning': warning})
      
    for i in weekdays:
      try:
        j = int(i)
      except:
        warning = 'Weekday value could not be parsed an an integer'
        return JsonResponse({'warning': warning})
      if j not in range(0, 7):
        warning = f'{i} is not a valid weekday'
        return JsonResponse({'warning': warning})
    if action != 'CMS' and action != 'MMA':
      warning = 'Action value must be CMS or MMA'
      return JsonResponse({'warning': warning})


    date = convert_tz(datetime.now(), tz_string)
    date_until = convert_tz(datetime.now(), tz_string)
    #Set end date to break the while loop
    if over_period == 'weeks':
      date_until += timedelta(weeks=quantityDWM)
    elif over_period == 'months':
      date_until = assert_tz(
        datetime(
          date_until.year + ((date_until.month + quantityDWM)//12),
          (date_until.month + quantityDWM)%12,
          date_until.day,
          date_until.hour,
          date_until.minute,
          date_until.second,
          date_until.microsecond
        ),
        tz_string
      )
    elif over_period == 'years':
      date_until = assert_tz(
        datetime(
          date_until.year + quantityDWM,
          date_until.month,
          date_until.day,
          date_until.hour,
          date_until.minute,
          date_until.second,
          date_until.microsecond
        ),
        tz_string
      )
    else:
      warning = f'"{over_period}" is not a valid response'
      return JsonResponse({'warning': warning})
    #While loop
    if quantityDWM >= 1 and quantityDWM <= 100:
      time_pattern = re.compile(r'^([01]\d|2[0-3]):([0-5]\d)$')
      alien_time = False
      while date <= date_until:
        for i in times:
          if time_pattern.match(i) is False:
            alien_time = True
            continue
          time = i.split(':')
          time = tuple(map(lambda x: int(x), time))


          aware_date = assert_tz(
            datetime(
              date.year,
              date.month,
              date.day,
              time[0],
              time[1],
              0,
            ),
            tz_string
          )
          if aware_date >= datetime.now(pytz.timezone(tz_string)) and str(aware_date.weekday()) in weekdays:
            if action == 'CMS':
              app_list.append(aware_date)
            elif action == 'MMA':
              for ser in service_list:
                app = Appointment(
                  business=request.user,
                  slot=aware_date,
                  service=ser
                )
                app_list.append(app)
        date += timedelta(days=1)
    if action == 'MMA':
      Appointment.objects.bulk_create(app_list)
    elif action == 'CMS':
      appointments = Appointment.objects.filter(
        business=request.user,
        slot__in=app_list,
        is_booked=False,
        service__in=service_list
      )
      appointments.delete()
    else:
      warning = 'Quantity of weeks/months/days must be between 1 and 100'
      return JsonResponse({'warning': warning})
    if alien_time:
      message = 'Schedule successfully updated with valid times! (Some errors in list of times due to javascript manipulation)'
    else:
      message = 'Schedule successfully updated!'
    return JsonResponse({'message': message})
  else:
    warning = 'GET requests forbidden'
    return JsonResponse({'warning': warning})

def retreive_dates(request, slug):
  if request.method == 'POST':
    try:
      data = json.loads(request.body)
      dates = data['dates']
      service_string = data['service']
      tz_string = data['timezone']
    except:
      warning = 'Form submission invalid'
      return JsonResponse({'warning': warning})

    try:
      business = CustomBusinessUser.objects.get(business_slug=slug)
    except:
      warning = 'Slug does not match existing user.'
      return JsonResponse({'warning': warning})

    try:
      if service_string != 'all_services':
        service = Service.objects.get(
          business=business.user,
          service=service_string
        )
      else:
        service = None
    except:
      warning = 'Service does not exist.'
      return JsonResponse({'warning': warning})
    current_time = datetime.now(pytz.timezone(tz_string))
    send_data = []
    for date in dates:
      date_iso = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ')
      
      date_object_start = datetime(
        date_iso.year,
        date_iso.month,
        date_iso.day,
        0,
        0
      )
      date_object_end = datetime(
        date_iso.year,
        date_iso.month,
        date_iso.day,
        23,
        59
      )
      date_object_start = assert_tz(date_object_start, tz_string)
      date_object_end = assert_tz(date_object_end, tz_string)
      
      appointments = Appointment.objects.filter(
          slot__gte=date_object_start, 
          slot__lte=date_object_end,
          business=business.user
        ).order_by('slot')
      if service is not None:
        appointments = appointments.filter(
          service=service
        )

      if appointments.exists():
        times = [[i.slot.isoformat(), i.is_booked] for i in appointments if i.slot > current_time]
        if len(times) > 0:
          send_data.append([date_iso, times])

    if len(send_data) <= 0:
      send_data = None
    return JsonResponse({'dates': send_data})
  else:
    warning = 'POST requests only permitted for this URL'
    return render(request, 'home/home.html', {'warning': warning})

def book_slot(request, slug):
  if request.method == 'POST':
    try:
      business = CustomBusinessUser.objects.get(business_slug=slug)
      business_stripe_account = get_stripe_user(business.user)
      iso = request.POST['iso-appointment']
      tz_string = request.POST['timezone']
      date = datetime.fromisoformat(iso)
      readable_date = (convert_tz(date, tz_string)).strftime("%d/%m/%Y @ %I:%M%p")
      service_string = request.POST['show-apps-for']
      all_services = None
      service = None
      services = None
      if service_string == 'all_services':
        services = Service.objects.filter(
          business=business.user
        )
        all_services = []
      else:
        service = Service.objects.get(
          business=business.user,
          service=service_string
        )
    except Exception as e:
      context = {
        'warning': 'Invalid form submission. Please try again.'
      }
      business = CustomBusinessUser.objects.filter(business_slug=slug)
      if business.exists():
        context['business_slug'] = slug
        context['replace_state'] = reverse('business_schedule', args=[slug])
        context['business_photo'] = business.first().photo.url if bool(business.first().photo) else False
        context['business_name'] = business.first().business_name
        context['business_bio'] = business.first().business_bio if business.first().business_bio is not None else False
        return render(request, 'business_schedule.html', context)
      else:
        return render(request, 'home.html', context)
    appointment = Appointment.objects.filter(business=business.user, slot=date)

    if services is not None:
      for ser in services:
        app = appointment.filter(
          service=ser,
          is_booked=False
        )
        if app.exists():
          all_services.append(ser)
          
    context = {
      'iso': iso,
      'date': readable_date,
      'timezone': tz_string,
      'business_slug': slug,
      'business_name': business.business_name,
      'stripe_id': business.stripe_id
    }
    if all_services is not None:
      context['all_services'] = all_services
      return render(request, 'book_appointment.html', context=context)
    elif service is not None:
      context['service'] = service
      return render(request, 'book_appointment.html', context=context)
    else:
      return redirect('business_schedule', slug=business.business_slug)

def create_payment_intent(request, slug):
  try:
    business = CustomBusinessUser.objects.get(
      business_slug=slug
    )
    business_stripe_user = get_stripe_user(business.user)
    service = Service.objects.get(
      business=business.user,
      service=request.POST['service']
    )
    iso = request.POST['iso']
    date = datetime.fromisoformat(iso)
    readable_date = (date).strftime("%d/%m/%Y @ %I:%M%p")
    price = int(request.POST['price'])
  except:
    warning = 'Invalid form submission. Please try again.'
    return JsonResponse({'warning': warning})

  appointment = Appointment.objects.filter(
    business=business.user,
    slot=date,
    service=service,
    is_booked=False
  )
  if appointment.exists() and business_stripe_user is not None and price == service.price:
    description = f'{service.service} @ {readable_date}'
    amount = service.price
    my_percentage = 0.1
    application_fee = int(amount * my_percentage)
    intent = stripe.PaymentIntent.create(
      amount=amount,
      description=description,
      currency='gbp',
      payment_method_types=['card'],
      capture_method='manual',
      #automatic_payment_methods={'enabled': True},
      application_fee_amount=application_fee,
      stripe_account=business.stripe_id
    )
    context = {
        'client_secret': intent.client_secret,
        'intent_id': intent.id,
      }
    return JsonResponse(context)
  else:
    warning = "The appointment that you are attempting to book has become unavailable. Please navigate to the business' schedule and choose another."
    return JsonResponse({'warning': warning})
      
def handle_payment(request, slug):
  if request.method == 'POST':
    try:
      business = CustomBusinessUser.objects.get(business_slug=slug)
      business_tz = business.pref_tz
      client_accept = request.POST['client_accepts']
      if client_accept != 'accepted':
        raise Exception
      iso = request.POST['iso-appointment']
      tz_string = request.POST['timezone']
      intent_id = request.POST['intent_id']
      #client_secret = request.POST['client_secret']
      client_name = trim(request.POST['client-name'])
      client_email = trim(request.POST['client-email'])
      client_phone = trim(request.POST['telephone'])
      client_address = (
        trim(request.POST['address-line-1']) + ', ',
        trim(request.POST['address-line-2']) + ', ',
        trim(request.POST['city']) + ', ',
        trim(request.POST['county']) + ', ',
        trim(request.POST['post-code'])
      )
      client_address = f'{client_address[0]}{client_address[1]}{client_address[2]}{client_address[3]}{client_address[4]}'
      client_note = request.POST['note'].replace('\r', '').replace('\n', '<br>')
      service_ref = json.loads(request.POST['service'])['service'];
      date = datetime.fromisoformat(iso)
      readable_date = (convert_tz(date, tz_string)).strftime("%d/%m/%Y @ %I:%M%p")
      business_readable_date = (convert_tz(date, business_tz)).strftime("%d/%m/%Y @ %I:%M%p")
      service = Service.objects.get(business=business.user, service=service_ref)
    except Exception as e:
      context = {
        'warning': 'Invalid form submission. This can happen if you untick the Terms and Conditions as the payment is proccessing or manipulating the Javascript code. Any pending funds in your bank will be cancelled and you won\'t be charged.'
      }
      business = CustomBusinessUser.objects.filter(business_slug=slug)
      if business.exists():
        context['business_slug'] = slug
        context['replace_state'] = reverse('business_schedule', args=[slug])
        context['business_photo'] = business.first().photo.url if bool(business.first().photo) else False
        context['business_name'] = business.first().business_name
        context['business_bio'] = business.first().business_bio if business.first().business_bio is not None else False
        return render(request, 'business_schedule.html', context)
      else:
        return render(request, 'home.html', context)
    try:
      appointment = Appointment.objects.filter(business=business.user, slot=date, is_booked=False, service=service)
      intent_check = Appointment.objects.filter(
        stripe_id=business.stripe_id,
        charge_id=intent_id
      )
      intent = stripe.PaymentIntent.retrieve(intent_id, stripe_account=business.stripe_id)
      if appointment.exists() and intent_check.exists() is False:
        if intent.status == 'requires_capture':
          verification_code = secrets.token_urlsafe(255)
          verification_hash = hash_value(verification_code)
          check_verification = Appointment.objects.filter(
            business=business.user,
            verification_code=verification_hash
          )
          while check_verification.exists():
            verification_code = secrets.token_urlsafe(255)
            verification_hash = hash_value(verification_code)
            check_verification = Appointment.objects.filter(
            business=business.user,
            verification_code=verification_hash
          )
          qr_img = generate_qr_code(
            request.build_absolute_uri(reverse('verify_appointment', args=[verification_code])),
            verification_code,
            'png'
          )
          app = appointment.first()
          app.is_booked = True
          app.client_accept = True
          app.charge_id = intent.id
          app.stripe_id = business.stripe_id
          app.name = client_name
          app.email = client_email
          app.service_reference = service.service
          app.price_reference = service.price
          app.telephone = client_phone
          app.address = client_address
          app.note = client_note
          app.currency_reference = service.currency
          app.verification_code = verification_hash
          app.qr_code = qr_img
          app.save()
          stripe.PaymentIntent.capture(
            intent=intent.id,
            stripe_account=business.stripe_id
          )
          name = client_name.split()[0]
          verification_url = request.build_absolute_uri(reverse('verify_appointment', args=[verification_code]))
          email_subject = f'Booking Reference: {app.charge_id}'
          email_message = f'Hello {name},\n\nThank you for booking with {business.business_name} for the service {app.service_reference}. Please keep the date safe in your diary:\n\n{readable_date} - {tz_string} Timezone\n\nWe look forward to seeing you!\n\nPlease forward this link to us on attending the booking so we can verify you: {verification_url}'
          html_message = '''
          <p>Hello {name},</p>
          <p>Thank you for booking with {bn} for the service {sr}.</p>
          <p>Please keep the date safe in your diary: {readable_date} - {tz_string} Timezone</p>
          <p>We look forward to seeing you! Don\'t forget to let us scan your QR code below to verify your booking!</p>
          <img src="{qr_url}" alt="QR Verification" style="width: 100%; max-width: 300px; dislay: block; margin: 30px auto;">
          <p style="font-size: 7px;">If you can\'t see the QR image, please forward this link to us: {verify_url}</p>'''.format(
            qr_url=request.build_absolute_uri(app.qr_code.url),
            name=name,
            sr=app.service_reference,
            bn=business.business_name,
            readable_date=readable_date,
            tz_string=tz_string,
            verify_url=verification_url
          )
          send_mail(email_subject, email_message, 'info@potterbook.co', [client_email], html_message=html_message)
          send_mail(
            f'New Booking: {client_name}',
            f'Customer Name: {client_name}\nEmail: {client_email}\nBooked For: {business_readable_date} - {business_tz} Timezone\nService Required: {service.service}\nPayment Ref: {app.charge_id}\n',
            'info@potterbook.co',
            [business.user.email]
          )
          context = {
            'email': client_email,
            'readable_date': f'{readable_date} - {tz_string} Timezone',
            'pay_ref': app.charge_id 
          }
          return render(request, 'payment_success.html', context=context)
        else:
          context = {
            'warning': 'Payment Declined. Please try again.',
            'business_slug': slug,
            'business_photo': business.photo.url if bool(business.photo) else False,
            'business_name': business.business_name,
            'business_bio': business.business_bio if business.business_bio is not None else False,
            'replace_state': reverse('business_schedule', args=[slug])
        }
        return render(request, 'business_schedule.html', context)
      elif intent_check.exists() is True:
        context = {
          'warning': 'Payment Intent ID already exists for Stripe account. Please don\'t try hack us :-).',
          'business_slug': slug,
          'business_photo': business.photo.url if bool(business.photo) else False,
          'business_name': business.business_name,
          'business_bio': business.business_bio if business.business_bio is not None else False,
          'replace_state': reverse('business_schedule', args=[slug])
        }
        return render(request, 'business_schedule.html', context)
      else:
        stripe.PaymentIntent.cancel(
          intent=intent.id,
          stripe_account=business.stripe_id
        )
        context = {
          'warning': 'The requested appointment is not available and you will not be charged. Any pending funds in your bank account will clear within 7 days. Please choose another appointment',
          'business_slug': slug,
          'business_photo': business.photo.url if bool(business.photo) else False,
          'business_name': business.business_name,
          'business_bio': business.business_bio if business.business_bio is not None else False,
          'replace_state': reverse('business_schedule', args=[slug])
        }
        return render(request, 'business_schedule.html', context)
    except:
      intent_to_cancel = stripe.PaymentIntent.retrieve(
        intent_id,
        stripe_account = business.stripe_id
      )
      if intent_to_cancel.status == 'requires_capture':
        stripe.PaymentIntent.cancel(
            intent=intent_id,
            stripe_account=business.stripe_id
          )
      elif intent_to_cancel.status == "succeeded":
        stripe.Refund.create(
            payment_intent=intent_id,
            stripe_account=business.stripe_id,
            reason='duplicate',
            refund_application_fee=True
          )
      context = {
        'warning': 'The requested appointment is not available and you will not be charged. Any pending funds in your bank account will clear within 7 days. Please choose another appointment',
        'business_slug': slug,
        'business_photo': business.photo.url if bool(business.photo) else False,
        'business_name': business.business_name,
        'business_bio': business.business_bio if business.business_bio is not None else False,
        'replace_state': reverse('business_schedule', args=[slug])
      }
      return render(request, 'business_schedule.html', context)
'''
def business_schedule(request, slug):
  try:
    subdomain = request.META['HTTP_HOST'].split('.')[0]
    business = CustomBusinessUser.objects.get(business_slug=subdomain)
  except:
    warning = f'Business with slug name "{subdomain}" does not exist.'
    return render(request, 'home/home.html', {'warning': warning})

  stripe_user = get_stripe_user(business.user)
  context = {
    'business_name': business.business_name,
    'business_slug': slug,
    'business_photo': business.photo.url if bool(business.photo) else False,
    'business_bio': business.business_bio if business.business_bio is not None else False,
    'stripe_enabled': bool(stripe_user),
    'business_services': Service.objects.filter(business=business.user)
  }
  if stripe_user is None:
    if business.business_name[-1] == 's':
      possesive_apostrophe = "'"
    else:
      possesive_apostrophe = "'s"
    context['warning'] = f'{business.business_name}{possesive_apostrophe} schedule is not available at the moment. Please check back soon!'
    return render(request, 'business_schedule.html', context)
  else: 
    return render(request, 'business_schedule.html', context)
'''

def verify_appointment(request, code):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated:
    try:
      hash = hash_value(code)
      appointment = Appointment.objects.get(
        business=request.user,
        verification_code=hash
      )
      already_verified = appointment.verified
      appointment.qr_code.delete()
      appointment.verified = True
      appointment.save()
      return render(request, 'verify_appointment.html', {
        'verified': True,
        'already_verified': already_verified,
        'appointment': appointment
      })
    except Exception as e:
      return render(request, 'verify_appointment.html', {'verified': False})
  else:
    warning = 'User must be logged in to verify appointments'
    return render(request, 'home/home.html', {'warning': warning})

def fetch_appointments(request, page):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  try:
    tz_string = request.POST['timezone-filter']
    current_time = datetime.now(pytz.timezone(tz_string))
    service_string = request.POST['service']
    booked = request.POST['booked']
    verified = request.POST['verified']
    timeframe = request.POST['timeframe']
    service = None
    if service_string not in ['all', 'legacy']:
      service = Service.objects.get(
        business=request.user,
        service=service_string
      )
  except Exception as e:
    warning = 'Invalid form submission'
    return JsonResponse({'warning': warning})
  appointments = Appointment.objects.filter(
    business=request.user,
  )
  if timeframe == 'before_now':
    appointments = appointments.filter(
      slot__lt=current_time
    ).reverse()
  elif timeframe == 'now_onwards':
    appointments = appointments.filter(
      slot__gte=current_time
    )
  else:
    warning = 'Invalid form submission'
    return JsonResponse({'warning': warning})

  
  if service != None or service_string == 'legacy':
    appointments = appointments.filter(
      service=service
    )
  if booked != 'all':
    if booked == 'booked':
      appointments = appointments.filter(is_booked=True)
    elif booked == 'unbooked':
      appointments = appointments.filter(is_booked=False)
    else:
      warning = 'Invalid form submission'
      return JsonResponse({'warning': warning})
  if verified != 'all':
    if verified == 'verified':
      appointments = appointments.filter(verified=True)
    elif verified == 'unverified':
      appointments = appointments.filter(verified=False)
    else:
      warning = 'Invalid form submission'
      return JsonResponse({'warning': warning})
      
  appointments = appointments.order_by('slot')
  paginator = Paginator(appointments, 10)
  data = {
    'appointment_list': [],
    'prev_pages': [],
    'current_page': page,
    'next_pages': []
  }
  appointment_page = None
  if page in paginator.page_range:
    appointment_page = paginator.page(page)
    data['appointment_list'] = [
  {
    'id': i.id,
    'date': (convert_tz(i.slot, tz_string)).strftime("%d/%m/%Y @ %I:%M%p"),
    'service': i.service.service if i.service is not None else i.service_reference,
    'service_price': i.service.price if i.service is not None else i.price_reference,
    'booked': i.is_booked,
    'verified': i.verified,
    'charge_id': i.charge_id,
    'name': i.name,
    'email': i.email,
    'telephone': i.telephone,
    'address': i.address,
    'note': i.note,
    'service_booked': i.service_reference,
    'paid': i.price_reference,
    'refunded': i.refunded
} for i in appointment_page.object_list

]
    prev_num = page
    prev_check = paginator.page(prev_num)
    for i in range(0, 2):
      if prev_check.has_previous():
        data['prev_pages'].insert(0, prev_check.previous_page_number())
        prev_num -= 1
        prev_check = paginator.page(prev_num)
      else:
        break

    next_num = page
    next_check = paginator.page(next_num)
    for i in range(0, 2):
      if next_check.has_next():
        data['next_pages'].append(next_check.next_page_number())
        next_num += 1
        next_check = paginator.page(next_num)
      else:
        break

  return JsonResponse(data)

#Continue
def appointment_config(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.user.is_authenticated == False:
    warning = 'User must be logged in to access this view'
    return JsonResponse({'warning': warning})
  try:
    action = request.POST['action']
    date = None
    service = None
    appointment_id = None
    if action == 'MMA':
      tz_string = request.POST['aa-timezone']
      date = assert_tz(datetime(
        int(request.POST['add-year']),
        int(request.POST['add-month']),
        int(request.POST['add-date']),
        int(request.POST['add-hour']),
        int(request.POST['add-minutes'])
        ),
        tz_string
      )
    if 'appointment_id' in request.POST:
      appointment_id = int(request.POST['appointment_id'])
    if 'service' in request.POST:
      service_string = request.POST['service']
      service = Service.objects.get(
        business=request.user,
        service=service_string
      )
  except:
    warning = 'Invalid form submission'
    return JsonResponse({'warning': warning})
  if action == 'MMA' and service is not None and date is not None:
    Appointment.objects.create(
      slot=date,
      business=request.user,
      service=service
    )
    message = 'Appointment has been created successfully'
    return JsonResponse({'message': message})
  elif action == 'CMS' and appointment_id is not None:
    try:
      appointment = Appointment.objects.get(
        id=appointment_id,
        business=request.user,
        is_booked=False
      )
      appointment.delete()
      message = 'Appointment has successfully been removed'
      return JsonResponse({'message': message})
    except:
      warning = "Invalid form submission"
      return JsonResponse({'warning': warning})
  elif action == 'refund' and appointment_id is not None:
    try:
      appointment = Appointment.objects.get(
        id=appointment_id,
        business=request.user,
        is_booked=True,
        refunded=False
      )
      business = CustomBusinessUser.objects.get(
        user=request.user
      )
      stripe_id = business.stripe_id
      intent = appointment.charge_id
      refund = stripe.Refund.create(
        stripe_account=stripe_id,
        payment_intent=intent,
      )
      if refund.status == 'succeeded':
        appointment.refunded = True
        appointment.save()
        message = 'Refund has successfully been processed for this appointment'
        return JsonResponse({'message': message})
      else:
        warning = "Refund unsuccessful. Please go to your Stripe account and monitor the issue"
        return JsonResponse({'warning': warning})
    except:
      warning = "Invalid form submission"
      return JsonResponse({'warning': warning})

def pricing_page(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  return render(request, 'pricing.html')

def contact_page(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  return render(request, 'contact.html')

def forgot_password(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.method == 'POST':
    try:
      email = request.POST['email']
    except:
      warning = 'Invalid form submission'
      return JsonResponse({'warning': warning})

    
    try:
      user = User.objects.get(
        email=email
      )
      business = CustomBusinessUser.objects.get(
        user=user
      )
    except:
      return JsonResponse({'processed': True})
    url_secret = secrets.token_urlsafe(255)
    hash = hash_value(url_secret)
    business.password_reset_date = timezone.now()
    business.password_reset_code = hash
    business.save()
    subject = f'{company}: Password Reset'
    message = '''
    Hello {name},

    A request to change your password has been made. Please click the following link and follow the instructions to create a new password:

    {prl}

    If this wasn't you, please ignore this message. If you have any concerns over security, please contact us for any reassurance needed.

    Thanks,

    The {company} team.
    '''.format(
      name=user.first_name,
      prl=request.build_absolute_uri(reverse('reset_password', args=[url_secret])),
      company=company
    )
    mail_status = send_mail(
      subject=subject,
      message=message,
      from_email='info@potterbook.co',
      recipient_list=[user.email],
    )
    return JsonResponse({'processed': True})
  else:
    return render(request, 'forgotpassword/stepone.html')

def reset_password(request, code):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  if request.method == 'POST' and request.user.is_authenticated == False:
    try:
      hash = hash_value(code)
      business = CustomBusinessUser.objects.get(
        password_reset_code=hash
      )
      password = request.POST['password']
      password_confirm = request.POST['confirm-password']
    except:
      return JsonResponse({'changed': False})
    pass_check = validate_passwords(password, password_confirm)
    if pass_check is True:
      user = business.user
      user.set_password(password)
      user.save()
      business.password_reset_date = None
      business.password_reset_code = None
      business.save()
      return JsonResponse({'changed': True})
    else:
      return JsonResponse({'changed': False})
  elif request.user.is_authenticated == False:
    try:
      business = CustomBusinessUser.objects.get(
        password_reset_code=hash_value(code)
      )
    except:
      warning = 'Reset link not found. If you are having problems, please go through the password reset process again.'
      return render(request, 'home/home.html', {'warning': warning, 'replace_state': '/'})
    return render(request, 'forgotpassword/steptwo.html', {'code': code, 'business': business})
  else:
    warning = 'Logged in users can not access the password reset page.'
    return render(request, 'home/home.html', {'warning': warning, 'replace_state': '/'})

def terms_and_conditions(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  return render(request, 'terms_and_conditions.html')

def privacy_policy(request):
  subdomain = request.META['HTTP_HOST'].split('.')[0]
  if subdomain not in reg_subdoms:
    raise Http404('Invalid subdomain for this view.')
  return render(request, 'privacy_policy.html')
