"""AwesomeLocker URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from AwesomeLockerApp import views

urlpatterns = [
    # /rsa 负责分发rsa公钥
    url(r'^rsa-pk$', views.distribute_public_key, name='distribute_public_key'),
    # /aes 负责分发由rsa加密后的aes密码
    url(r'^aes-key$', views.distribute_aes_pwd, name='distribute_aes_pwd'),
]
