from django.db import models

# Create your models here.
class Product(models.Model):
    product_id = models.AutoField
    product_name = models.CharField(max_length=50)
    category = models.CharField(max_length=50, default="")  # Use double or single quotes for defaults
    subcategory = models.CharField(max_length=50, default="")
    price = models.IntegerField(default=0)
    desc = models.CharField(max_length=300)  # Use underscores instead of hyphens and spaces
    pub_date = models.DateField()
    image = models.ImageField(upload_to='shop/images', default="")  # Default value for the image field should be a string

    def __str__(self):
        return self.product_name  # Use double underscores before and after the method name
