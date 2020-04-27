from rest_framework.serializers import ModelSerializer, SerializerMethodField
from .models import APIManagerUser


class UserSerializer(ModelSerializer):

    email = SerializerMethodField()

    class Meta:
        model = APIManagerUser
        fields = ("uuid", "email", "last_login", "two_factor_enabled")
        read_only_fields = ("uuid", "last_login", "two_factor_enabled")

    def get_email(self, obj):
        return obj.primary_email.address
