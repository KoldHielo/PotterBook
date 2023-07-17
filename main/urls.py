from django.urls import path, re_path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve

urlpatterns = [
  path('', views.home, name='home'),
  path('login/', views.login_page, name='login'),
  path('register/', views.register, name='register'),
  path('profile/', views.profile, name='profile'),
  path('update-profile/', views.update_profile, name='update_profile'),
  path('connect/', views.connect, name='connect'),
  path('disconnect', views.disconnect, name='disconnect'),
  path('logout/', views.logout_click, name='logout'),
  re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
  re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
  path('editavailability/', views.edit_availability, name='edit_availability'),
  path('retreiveappointments/<str:slug>/', views.retreive_dates, name='retreive_dates'),
  path('business/<str:slug>/', views.business_schedule, name='business_schedule'),
  path('bookslot/<str:slug>/', views.book_slot, name='book_slot'),
  path('handlepayment/<str:slug>/', views.handle_payment, name='handle_payment'),
  path('appointmentavailable/<str:slug>/', views.appointment_available, name='appointment_available'),
  path('createpaymentintent/<str:slug>/', views.create_payment_intent, name='create_payment_intent'),
  path('verifyappointment/<str:code>/', views.verify_appointment, name="verify_appointment"),
  path('fetchappointments/<int:page>/', views.fetch_appointments, name='fetch_appointments'),
  path('appointmentconfig/', views.appointment_config, name='appointment_config'),
  path('pricing/', views.pricing_page, name='pricing_page'),
  path('contact/', views.contact_page, name='contact_page'),
  path('forgotpassword/', views.forgot_password, name='forgot_password'),
  path('resetpassword/<str:code>/', views.reset_password, name='reset_password'),
  path('termsandconditions/', views.terms_and_conditions, name='terms_and_conditions'),
  path('privacypolicy/', views.privacy_policy, name='privacy_policy'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)