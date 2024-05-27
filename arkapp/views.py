from django.shortcuts import render
from arkapp.models import Product
from math import ceil


# Create your views here.
def home(request):
    current_user = request.user
    print(current_user)
    allProds = []
    catprods = Product.objects.values('category', 'id')
    cats = {item['category'] for item in catprods}  # Corrected the key 'category'
    for cat in cats:  # Corrected the variable name
        prod = Product.objects.filter(category=cat)
        n = len(prod)
        nSlides = n // 4 + ceil((n / 4) - (n // 4))  # Corrected the calculation
        allProds.append([prod, range(1, nSlides), nSlides])
    params = {'allProds': allProds}  # Corrected the dictionary syntax
    return render(request, 'index.html', params)