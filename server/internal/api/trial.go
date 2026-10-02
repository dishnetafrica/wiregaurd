package api

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/ratelimit"
)

// Public "Request a free trial" page. No account is created here; the
// request waits for an administrator's approval in the dashboard.
type TrialPages struct {
	svc     *provision.Service
	byIP    *ratelimit.Limiter
	contact string
	tmpl    *template.Template
}

func NewTrialPages(svc *provision.Service, supportContact string) *TrialPages {
	return &TrialPages{svc: svc, byIP: ratelimit.New(3, time.Hour), contact: supportContact, tmpl: template.Must(template.New("trial").Parse(trialHTML))}
}

func (t *TrialPages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /trial", t.form)
	mux.HandleFunc("POST /trial", t.submit)
}

type trialView struct {
	Error, Done, Contact string
	Values               map[string]string
}

func (t *TrialPages) form(w http.ResponseWriter, r *http.Request) {
	t.render(w, http.StatusOK, trialView{Contact: t.contact, Values: map[string]string{"pcs": "2"}})
}

func (t *TrialPages) submit(w http.ResponseWriter, r *http.Request) {
	ip := clientIPOf(r)
	if err := r.ParseForm(); err != nil {
		t.render(w, http.StatusBadRequest, trialView{Error: "The form could not be read. Please try again.", Contact: t.contact, Values: map[string]string{}})
		return
	}
	v := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	values := map[string]string{"business": v("business"), "contact": v("contact"), "phone": v("phone"), "email": v("email"), "pcs": v("pcs"), "office": v("office"), "notes": v("notes")}
	// Honeypot: real browsers leave this hidden field empty.
	if v("website") != "" {
		t.render(w, http.StatusOK, trialView{Done: "Thank you. DishNet will contact you shortly.", Contact: t.contact, Values: values})
		return
	}
	if !t.byIP.Allow(ip) {
		t.render(w, http.StatusTooManyRequests, trialView{Error: "Too many requests from this connection. Please try again in an hour or call us.", Contact: t.contact, Values: values})
		return
	}
	pcs, _ := strconv.Atoi(v("pcs"))
	_, err := t.svc.SubmitTrialRequest(r.Context(), provision.TrialRequestInput{Business: v("business"), ContactName: v("contact"), Phone: v("phone"), Email: v("email"), PCs: pcs, OfficeType: v("office"), Notes: v("notes"), IP: ip})
	if err != nil {
		t.render(w, http.StatusBadRequest, trialView{Error: err.Error(), Contact: t.contact, Values: values})
		return
	}
	t.render(w, http.StatusOK, trialView{Done: "Thank you! Your request has been received. DishNet will call you to set up your office server and send you the install link for your computers.", Contact: t.contact, Values: values})
}

func (t *TrialPages) render(w http.ResponseWriter, status int, v trialView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := t.tmpl.Execute(w, v); err != nil {
		fmt.Fprint(w, "template error")
	}
}

const trialHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DishNet Secure Connect — Free trial</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f7f7f8;margin:0;color:#1f2328}
header{background:#d7262d;color:#fff;padding:18px 24px}header b{font-size:20px}header span{opacity:.85}
main{max-width:560px;margin:24px auto;padding:0 16px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:22px}
h1{font-size:22px;margin:0 0 6px}p.m{color:#6b7280;margin:0 0 18px;font-size:14px}
label{display:block;font-size:13px;color:#6b7280;margin:12px 0 4px}
input,select,textarea{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfd3d8;border-radius:6px;font:inherit;font-size:15px}
button{background:#d7262d;color:#fff;border:0;border-radius:6px;padding:11px 20px;font:inherit;font-size:15px;font-weight:600;margin-top:18px;cursor:pointer}
.err{background:#fee2e2;color:#a81b21;padding:10px 12px;border-radius:6px;margin-bottom:12px}
.ok{background:#dcfce7;color:#15803d;padding:14px;border-radius:6px;font-size:16px}
.hp{position:absolute;left:-9999px}
footer{color:#6b7280;font-size:12px;text-align:center;margin:18px 0}
</style></head><body>
<header><b>DishNet</b> <span>Secure Connect</span></header>
<main><div class="card">
{{if .Done}}<div class="ok">{{.Done}}</div>{{if .Contact}}<p class="m" style="margin-top:14px">Questions? Contact DishNet: {{.Contact}}</p>{{end}}
{{else}}
<h1>Try DishNet Secure Connect free for 30 days</h1>
<p class="m">Secure access to your office computer or server (Tally, ERP, accounting) from anywhere — over Starlink or any internet. No technical setup for your staff: they click a link and connect.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/trial">
<label>Business name</label><input name="business" required maxlength="80" value="{{index .Values "business"}}">
<label>Contact person</label><input name="contact" required maxlength="80" value="{{index .Values "contact"}}">
<label>Phone (we will call you)</label><input name="phone" required inputmode="tel" placeholder="0705 993 348" value="{{index .Values "phone"}}">
<label>Email (optional)</label><input name="email" type="email" maxlength="120" value="{{index .Values "email"}}">
<label>How many staff computers need access?</label><input name="pcs" type="number" min="1" max="14" required value="{{index .Values "pcs"}}">
<label>Where is your office software running?</label>
<select name="office"><option value="windows_pc">On a Windows PC in the office</option><option value="windows_server">On a Windows Server</option><option value="unknown">Not sure</option></select>
<label>Anything else? (optional)</label><textarea name="notes" rows="3" maxlength="500">{{index .Values "notes"}}</textarea>
<div class="hp"><label>Website</label><input name="website" tabindex="-1" autocomplete="off"></div>
<button>Request my free trial</button>
</form>
<p class="m" style="margin-top:16px">After you submit, DishNet confirms your details, helps set up the office computer, and sends an install link to each staff computer. The trial ends automatically after 30 days unless you continue.</p>
{{end}}
</div><footer>Encrypted connection · Authorized devices only · Powered by WireGuard®</footer></main></body></html>`
