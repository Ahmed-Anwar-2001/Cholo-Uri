from django.db import models

# Create your models here.

# Create your models here.
import mongoengine as me
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

# ----- User and Authentication -----
class User(me.Document):
    ROLES = ('shop_owner', 'shop_employee', 'customer', 'admin', 'superadmin')

    username    = me.StringField(required=True)
    email       = me.EmailField(required=True, unique=True)
    password    = me.StringField(required=True)
    role        = me.StringField(choices=ROLES, default='customer')
    is_active   = me.BooleanField(default=True)
    created_at  = me.DateTimeField(default=timezone.now)
    updated_at  = me.DateTimeField(default=timezone.now)

    meta = {
        'collection': 'users',
        'indexes': ['email'],
    }

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.updated_at = timezone.now()
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    @property
    def is_shop_owner(self):
        return self.role == 'shop_owner'

    @property
    def is_shop_employee(self):
        return self.role == 'shop_employee'

class Shop(me.Document):
    owner       = me.ReferenceField(User, reverse_delete_rule=me.CASCADE)
    name        = me.StringField(required=True)
    slogan      = me.StringField()
    domain      = me.StringField()
    email          = me.EmailField(null=True)
    phone          = me.StringField(null=True)
    address_line1  = me.StringField(null=True)
    address_line2  = me.StringField(null=True)
    city           = me.StringField(null=True)
    state          = me.StringField(null=True)
    country        = me.StringField(null=True)
    template    = me.ReferenceField('Template', null=True)
    style_pack  = me.ReferenceField('StylePack', null=True)
    settings    = me.DictField(default=dict)
    created_at  = me.DateTimeField(default=timezone.now)
    updated_at  = me.DateTimeField(default=timezone.now)

    meta = {
        'collection': 'shops',
        'indexes': ['domain'],
    }

    @property
    def employees(self):
        return User.objects.filter(id__in=[e.user.id for e in ShopEmployee.objects(shop=self)])
    
# ----- Shop and Employees -----
class ShopEmployee(me.Document):
    shop        = me.ReferenceField('Shop', reverse_delete_rule=me.CASCADE)
    user        = me.ReferenceField(User, reverse_delete_rule=me.CASCADE)
    is_manager  = me.BooleanField(default=False)
    assigned_at = me.DateTimeField(default=timezone.now)

    meta = {
        'collection': 'shop_employees',
        'indexes': ['shop', 'user'],
    }




# ----- Templates & Styles -----
class Template(me.Document):
    CATEGORIES = ('minimalist', 'luxury', 'vintage')

    name          = me.StringField(required=True)
    category      = me.StringField(choices=CATEGORIES)
    preview_image = me.StringField()  # store path or URL
    metadata      = me.DictField(default=dict)
    created_at    = me.DateTimeField(default=timezone.now)

    meta = {
        'collection': 'templates',
    }

class StylePack(me.Document):
    name       = me.StringField(required=True)
    settings   = me.DictField(default=dict)
    created_at = me.DateTimeField(default=timezone.now)

    meta = {
        'collection': 'style_packs',
    }


# ----- Products & Inventory -----
class ProductCategory(me.Document):
    shop   = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    name   = me.StringField(required=True)
    parent = me.ReferenceField('self', null=True)

    meta = {'collection': 'product_categories'}

class Product(me.Document):
    shop        = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    name        = me.StringField(required=True)
    slug        = me.StringField(required=True, unique_with='shop')
    description = me.StringField()
    category    = me.ReferenceField(ProductCategory, null=True)
    metadata    = me.DictField(default=dict)
    created_at  = me.DateTimeField(default=timezone.now)
    updated_at  = me.DateTimeField(default=timezone.now)

    meta = {
        'collection': 'products',
        'indexes': ['shop', 'slug'],
    }

class SKU(me.Document):
    product        = me.ReferenceField(Product) #, reverse_delete_rule=me.CASCADE
    sku_code       = me.StringField(required=True, unique=True)
    price          = me.DecimalField(required=True, precision=2)
    currency       = me.StringField(default='USD')
    inventory_count= me.IntField(default=0)
    attributes     = me.DictField(default=dict)

    meta = {'collection': 'skus'}


# ----- Orders & Transactions -----
class OrderItem(me.EmbeddedDocument):
    sku        = me.ReferenceField(SKU) #, reverse_delete_rule=me.CASCADE
    quantity   = me.IntField(required=True)
    unit_price = me.DecimalField(required=True, precision=2)

class Order(me.Document):
    STATUS = ('pending', 'processing', 'completed', 'cancelled')

    shop             = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    customer         = me.ReferenceField(User, null=True)
    status           = me.StringField(choices=STATUS, default='pending')
    items            = me.EmbeddedDocumentListField(OrderItem)
    total_amount     = me.DecimalField(precision=2)
    currency         = me.StringField(default='USD')
    shipping_address = me.DictField(default=dict)
    created_at       = me.DateTimeField(default=timezone.now)
    updated_at       = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'orders'}

class PaymentGatewayConfig(me.Document):
    PROVIDERS = ('stripe', 'paypal', 'twilio', 'custom')

    shop       = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    provider   = me.StringField(choices=PROVIDERS)
    config     = me.DictField(default=dict)
    is_active  = me.BooleanField(default=True)
    created_at = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'payment_gateways'}

class PaymentTransaction(me.Document):
    order          = me.ReferenceField(Order, reverse_delete_rule=me.CASCADE)
    gateway        = me.ReferenceField(PaymentGatewayConfig, reverse_delete_rule=me.DENY) #, reverse_delete_rule=me.PROTECT
    transaction_id = me.StringField(required=True, unique=True)
    amount         = me.DecimalField(precision=2)
    currency       = me.StringField(default='USD')
    status         = me.StringField()
    created_at     = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'payment_transactions'}


# ----- AI Agent & RAG -----
class KnowledgeBase(me.Document):
    shop            = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    name            = me.StringField(required=True)
    description     = me.StringField()
    vector_index_id = me.StringField(required=True)
    created_at      = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'knowledge_bases'}

class Document(me.Document):
    kb          = me.ReferenceField(KnowledgeBase, reverse_delete_rule=me.CASCADE)
    title       = me.StringField(required=True)
    content     = me.StringField()
    metadata    = me.DictField(default=dict)
    source_url  = me.URLField()
    created_at  = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'kb_documents'}

class ChatAgentConfig(me.Document):
    shop            = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    name            = me.StringField(required=True)
    rag_enabled     = me.BooleanField(default=True)
    rag_kb          = me.ReferenceField(KnowledgeBase, null=True)
    fallback_human  = me.BooleanField(default=False)
    config          = me.DictField(default=dict)
    created_at      = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'chat_agent_configs'}

class VoiceAgentConfig(me.Document):
    shop            = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    name            = me.StringField(required=True)
    stt_provider    = me.StringField()
    tts_provider    = me.StringField()
    telephony_conf  = me.DictField(default=dict)
    rag_kb          = me.ReferenceField(KnowledgeBase, null=True)
    config          = me.DictField(default=dict)
    created_at      = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'voice_agent_configs'}

# ----- Embeddings Tracking -----
class EmbeddingRecord(me.Document):
    content_type = me.StringField(required=True)
    object_id    = me.StringField(required=True)
    external_id  = me.StringField()
    created_at   = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'embedding_records'}

# ----- Marketing Campaigns -----
class MarketingCampaign(me.Document):
    CHANNELS    = ('email', 'sms', 'social')

    shop        = me.ReferenceField(Shop, reverse_delete_rule=me.CASCADE)
    name        = me.StringField(required=True)
    channel     = me.StringField(choices=CHANNELS)
    template    = me.DictField(default=dict)
    channels    = me.ListField(me.StringField())
    schedule_at = me.DateTimeField()
    is_active   = me.BooleanField(default=False)
    created_at  = me.DateTimeField(default=timezone.now)

    meta = {'collection': 'marketing_campaigns'}