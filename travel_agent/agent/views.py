from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect, HttpResponse
from db_connection import *
from django.contrib import messages
from django.utils import timezone
from django.core.validators import validate_email
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth.password_validation import validate_password, ValidationError as PasswordValidationError
from django.utils.http import url_has_allowed_host_and_scheme
from django.conf import settings
import mongoengine.errors as me_errors
import re
from .models import *
# Create your views here.

def home(request):
    return render(request, 'home\home.html')


def feed(request):
    return render(request, "dashboard\\feed.html")

# views.py


@csrf_protect
@require_http_methods(["GET", "POST"])
def login(request):
    """
    Renders and processes the login form.
    On success: stores user_id and role in session, redirects to 'next' or dashboard.
    """
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')

        # 1) Required fields
        if not email or not password:
            messages.error(request, "Both email and password are required.")
            return redirect('login')

        # 2) Email format
        try:
            validate_email(email)
        except DjangoValidationError:
            messages.error(request, "Enter a valid email address.")
            return redirect('login')

        # 3) Lookup user
        user = User.objects(email=email).first()
        if not user or not user.is_active:
            messages.error(request, "Invalid credentials.")
            return redirect('login')

        # 4) Password check
        if not user.check_password(password):
            messages.error(request, "Invalid credentials.")
            return redirect('login')

        # 5) All good — log the user in
        request.session.flush()  # clear out any old session data
        request.session['user_id'] = str(user.id)
        request.session['role'] = user.role
        # optional: set session expiry (e.g. 2 weeks)
        request.session.set_expiry(settings.SESSION_COOKIE_AGE)

        messages.success(request, f"Welcome back, {user.username}!")

        # 6) Safe redirect to next or dashboard
        next_url = request.GET.get('next', '')
        if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
            return redirect(next_url)
        return redirect('feed')

    # GET
    return render(request, 'auth/login.html')








USERNAME_REGEX = r'^[\w.@+-]+$'  # letters, digits and @/./+/-/_


@csrf_protect
@require_http_methods(["GET", "POST"])
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        firstname = request.POST.get('firstname', '').strip()
        lastname = request.POST.get('lastname', '').strip()
        email = request.POST.get('email', '').strip().lower()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')

        # 1. Required fields
        if not (username and email and password1 and password2 and firstname and lastname):
            messages.error(request, "All fields are required.")
            return redirect('register')

        # 2. Username format
        if not re.match(USERNAME_REGEX, username):
            messages.error(request, "Username may contain only letters, digits and @/./+/-/_ characters.")
            return redirect('register')

        # 3. Password match
        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        # 4. Password strength
        try:
            validate_password(password1)
        except PasswordValidationError as e:
            for msg in e.messages:
                messages.error(request, msg)
            return redirect('register')

        # 5. Email format
        try:
            validate_email(email)
        except DjangoValidationError:
            messages.error(request, "Enter a valid email address.")
            return redirect('register')

        # 6. Check duplicate email and username
        if User.objects(email=email).first():
            messages.error(request, "An account with that email already exists.")
            return redirect('register')
        
        if User.objects(username=username).first():
            messages.error(request, "Username already exists.")
            return redirect('register')

        # 7. All good, create user
        try:
            user = User(
                username=username,
                email=email,
                first_name=firstname,
                last_name=lastname, 
                role='customer',               # force default role
                is_active=True,
                created_at=timezone.now(),
                updated_at=timezone.now()
            )
            user.set_password(password1)
            messages.success(request, "Registration successful! Please sign in.")
            return redirect('login')

        except me_errors.ValidationError:
            messages.error(request, "Failed to create account; please try again.")
            return redirect('register')

    # GET
    return render(request, 'auth/register.html')
    


def logout(request):
    request.session.flush()
    return redirect('login')





def shop_info(request):
    # 1) Ensure the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    # 2) Load the User from Mongo
    user = User.objects(id=user_id).first()
    if not user:
        # session was stale, kick them back to login
        request.session.flush()
        return redirect('login')

    # 3) Fetch the Shop whose owner is that User
    shop = Shop.objects(owner=user).first()
    if not shop:
        # Shopper doesn’t yet have a shop? Redirect or show an error
        return render(request, 'no_shop.html')

    # 4) Render your shop_info.html with the `shop` context
    return render(request, 'shop_info.html', {
        'shop': shop,
    })

def shop_info_edit(request):
    # 1) Ensure the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    # 2) Load the User from Mongo
    user = User.objects(id=user_id).first()
    if not user:
        request.session.flush()
        return redirect('login')

    # 3) Fetch the Shop whose owner is that User
    shop = Shop.objects(owner=user).first()
    if not shop:
        return render(request, 'no_shop.html')

    # 4) Handle form submission manually
    if request.method == 'POST':
        # Update basic info
        shop.name           = request.POST.get('name', shop.name).strip()
        shop.slogan         = request.POST.get('slogan', shop.slogan).strip()
        shop.domain         = request.POST.get('domain', shop.domain).strip()
        shop.email          = request.POST.get('email', shop.email).strip() or None
        shop.phone          = request.POST.get('phone', shop.phone).strip() or None

        # Update address
        shop.address_line1  = request.POST.get('address_line1', shop.address_line1).strip() or None
        shop.address_line2  = request.POST.get('address_line2', shop.address_line2).strip() or None
        shop.city           = request.POST.get('city', shop.city).strip() or None
        shop.state          = request.POST.get('state', shop.state).strip() or None
        shop.country        = request.POST.get('country', shop.country).strip() or None

        # Save
        shop.updated_at = timezone.now()
        shop.save()
        # Redirect back to shop info page (no ID needed)
        return redirect('shop_info')

    # 5) Render form with existing shop data
    return render(request, 'shop_info_edit.html', {'shop': shop})


import os
import json
import uuid
from datetime import datetime
from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from groq import Groq
from django.utils import timezone

# Add this import for Whisper transcription
from openai import OpenAI                              # v1.x client

# System prompt guiding the LLM to use the tools by shop_id in session
SYSTEM_PROMPT = '''\
You are e-bitan Customer Support.

When the user needs the current UTC time, respond with exactly:
{"tool": "get_current_time", "args": {}}

When the user needs shop details (based on the shop_id stored in session), respond with exactly:
{"tool": "get_shop_info", "args": {}}

When the user wants to update shop information (based on the shop_id in session), respond with exactly:
{"tool": "update_shop_info", "args": {"<field>": "<new_value>", ...}}

For all other questions, answer in plain text.

Examples:
User: What is the current UTC time?
Assistant: {"tool": "get_current_time", "args": {}}

User: Show me the details of my shop.
Assistant: {"tool": "get_shop_info", "args": {}}

User: Change the shop slogan to "Quality First".
Assistant: {"tool": "update_shop_info", "args": {"slogan": "Quality First"}}
'''

@csrf_exempt
def agentic_chat(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    # ── 1) Audio‐first transcription ───────────────────────────────
    user_messages = []

    if request.FILES.get("audio"):
        # Load Whisper client
        stt_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        audio_file = request.FILES["audio"]
        try:
            resp = stt_client.audio.transcriptions.create(
                model="gpt-4o-transcribe",
                file=audio_file
            )
            transcript = resp.text.strip()
            # Insert as first user message
            user_messages.append({"role": "user", "content": transcript})
        except Exception as e:
            return JsonResponse({"error": f"Transcription failed: {e}"}, status=500)

        # Now also parse any JSON payload for parameters (optional)
        try:
            payload = json.loads(request.POST.get("payload", "{}"))
        except json.JSONDecodeError:
            payload = {}
    else:
        # ── 2) Fallback to JSON‐only path ───────────────────────────
        try:
            payload = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)
        user_messages = payload.get("messages", [])

    if not user_messages:
        return JsonResponse({"error": "No input provided"}, status=400)

    # ── 3) Model parameters & Groq client ─────────────────────────
    model_name  = payload.get("model", "llama-3.3-70b-versatile")
    temperature = payload.get("temperature", 0.6)
    top_p       = payload.get("top_p", 1)
    max_t_tool  = payload.get("max_tokens", 512)
    max_t_norm  = payload.get("max_tokens", 1024)

    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        return JsonResponse({"error": "GROQ_API_KEY not set in environment"}, status=500)
    client = Groq(api_key=groq_key)

    # ── 4) Tool implementations ────────────────────────────────────
    def get_current_time():
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def get_shop_info():
        shop_id = request.session.get("shop_id")
        if not shop_id:
            return json.dumps({"error": "No shop_id in session"})
        shop = Shop.objects(id=shop_id).first()
        if not shop:
            return json.dumps({"error": f"No shop found with id '{shop_id}'"})
        data = {
            "id": str(shop.id),
            "owner_id": str(shop.owner.id),
            "name": shop.name,
            "slogan": shop.slogan,
            "domain": shop.domain,
            "email": shop.email,
            "phone": shop.phone,
            "address_line1": shop.address_line1,
            "address_line2": shop.address_line2,
            "city": shop.city,
            "state": shop.state,
            "country": shop.country,
            "template_id": str(shop.template.id) if shop.template else None,
            "style_pack_id": str(shop.style_pack.id) if shop.style_pack else None,
            "settings": shop.settings,
            "created_at": shop.created_at.isoformat(),
            "updated_at": shop.updated_at.isoformat(),
        }
        return json.dumps(data)

    def update_shop_info(**fields):
        shop_id = request.session.get("shop_id")
        if not shop_id:
            return json.dumps({"error": "No shop_id in session"})
        shop = Shop.objects(id=shop_id).first()
        if not shop:
            return json.dumps({"error": f"No shop found with id '{shop_id}'"})
        updated = {}
        for key, value in fields.items():
            if hasattr(shop, key):
                setattr(shop, key, value)
                updated[key] = value
        if updated:
            shop.updated_at = timezone.now()
            shop.save()
            return json.dumps({"success": True, "updated_fields": updated})
        return json.dumps({"error": "No valid fields to update"})

    tools = {
        "get_current_time":  {
            "description": "Returns the current UTC time.",
            "function":    get_current_time,
        },
        "get_shop_info":     {
            "description": "Returns all stored fields for the current shop.",
            "function":    get_shop_info,
        },
        "update_shop_info":  {
            "description": "Updates shop fields for the current shop.",
            "function":    update_shop_info,
        },
    }

    # ── 5) Build conversation & first-pass tool decision ──────────
    convo     = [{"role": "system", "content": SYSTEM_PROMPT}] + user_messages
    first_rsp = client.chat.completions.create(
        model=model_name,
        messages=convo,
        temperature=temperature,
        max_completion_tokens=max_t_tool,
        top_p=top_p,
        stream=False,
    )
    raw = first_rsp.choices[0].message.content.strip()

    try:
        call       = json.loads(raw)
        tool_name  = call["tool"]
        args       = call.get("args", {})
        tool_res   = tools[tool_name]["function"](**args)

        # Determine tool_call_id
        msg   = first_rsp.choices[0].message
        tcalls = getattr(msg, "tool_calls", None) or []
        tool_call_id = (
            tcalls[0].get("tool_call_id") or tcalls[0].get("id")
            if tcalls else str(uuid.uuid4())
        )

        convo.append({"role": "assistant", "content": raw})
        convo.append({
            "role":         "tool",
            "name":         tool_name,
            "content":      tool_res,
            "tool_call_id": tool_call_id,
        })

        FOLLOWUP = (
            "You are e-bitan Customer Support. Now that the tool has run, "
            "reply in plain text with just the resulting information."
        )
        followup_msgs = [{"role": "system", "content": FOLLOWUP}] + convo[1:]
        completion = client.chat.completions.create(
            model=model_name,
            messages=followup_msgs,
            temperature=temperature,
            max_completion_tokens=max_t_tool,
            top_p=top_p,
            stream=True,
        )

    except (json.JSONDecodeError, KeyError):
        # No valid tool call → normal response
        completion = client.chat.completions.create(
            model=model_name,
            messages=convo,
            temperature=temperature,
            max_completion_tokens=max_t_norm,
            top_p=top_p,
            stream=True,
        )

    # ── 6) Stream back via SSE ────────────────────────────────────
    def event_stream():
        for chunk in completion:
            delta = chunk.choices[0].delta.content or ""
            yield f"data: {delta}\n\n"

    return StreamingHttpResponse(
        event_stream(),
        content_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        },
    )




