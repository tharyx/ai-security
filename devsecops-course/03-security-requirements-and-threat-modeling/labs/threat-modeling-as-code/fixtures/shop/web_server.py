"""Shop web tier (fixture: only parsed for annotations, never imported)."""

# @connects Internet:Browser to DMZ:WebServer with HTTPS
# @exposes DMZ:WebServer to Spoofing with a stolen session cookie
# @mitigates DMZ:WebServer against Spoofing with short-lived signed session cookies
def handle_request(request):
    return render(request)


# @exposes DMZ:WebServer to Tampering with unvalidated form fields
# @mitigates DMZ:WebServer against Tampering with server-side schema validation
# @exposes DMZ:WebServer to Denial of Service with unbounded request bodies
# @accepts Denial of Service to DMZ:WebServer with the CDN absorbs volumetric floods (risk owner: ops, review 2027-01)
def parse_form(body):
    return {}


# @connects DMZ:WebServer to Internal:PaymentService with mutual TLS
def call_payments(order):
    return None
