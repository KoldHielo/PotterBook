from django.db.models.signals import pre_delete
from django.dispatch import receiver
from main.models import CustomBusinessUser
import boto3

@receiver(pre_delete, sender=CustomBusinessUser)
def delete_s3_bucket(sender, instance, **kwargs):
  s3 = boto3.resource('s3')
  bucket = s3.Bucket('potterbook')
  for obj in bucket.objects.filter(Prefix=f'businesses/{instance.id}/'):
    s3.Object(bucket.name, obj.key).delete()
