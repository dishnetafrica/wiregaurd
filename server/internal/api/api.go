// Package api is the device-facing HTTPS API used by the Windows client.
// Every handler validates input strictly, never echoes secrets, and returns
// a stable machine-readable error code the client can map to a message.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/ratelimit"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
)

const maxBody = 16 << 10

type Handler struct {
	svc        *provision.Service
	log        *slog.Logger
	trustProxy bool
	// Activation is the most sensitive endpoint: brute-forcing codes must be
	// impractical even though codes carry 80 bits of entropy.
	activateByIP *ratelimit.Limiter
	deviceByIP   *ratelimit.Limiter
}

func New(svc *provision.Service, log *slog.Logger, trustProxy bool) *Handler {
	return &Handler{
		svc: svc, log: log, trustProxy: trustProxy,
		activateByIP: ratelimit.New(5, 10*time.Minute),
		deviceByIP:   ratelimit.New(120, time.Minute),
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health", h.health)
	mux.HandleFunc("POST /api/v1/activate", h.activate)
	mux.HandleFunc("GET /api/v1/device/config", h.withDevice(h.config))
	mux.HandleFunc("POST /api/v1/device/heartbeat", h.withDevice(h.heartbeat))
	mux.HandleFunc("POST /api/v1/device/rotate-key", h.withDevice(h.rotateKey))
}

// ---------- helpers ----------

type apiError struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: msg, Code: code})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "bad_content_type", "expected application/json")
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_json", "request body is not valid")
		return false
	}
	return true
}

func (h *Handler) clientIP(r *http.Request) string {
	if h.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if a, err := netip.ParseAddr(first); err == nil {
				return a.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- handlers ----------

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type activateRequest struct {
	Code          string   `json:"code"`
	PublicKey     string   `json:"public_key"`
	DeviceName    string   `json:"device_name"`
	OS            string   `json:"os"`
	ClientVersion string   `json:"client_version"`
	LANSubnets    []string `json:"lan_subnets,omitempty"`
}

type activateResponse struct {
	DeviceToken string                 `json:"device_token"`
	Config      provision.DeviceConfig `json:"config"`
}

func (h *Handler) activate(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	if !h.activateByIP.Allow(ip) {
		w.Header().Set("Retry-After", "600")
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many activation attempts; try again later")
		return
	}
	var req activateRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.LANSubnets) > 8 {
		writeErr(w, http.StatusBadRequest, "bad_request", "too many LAN subnets")
		return
	}
	var lans []netip.Prefix
	for _, s := range req.LANSubnets {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_lan", "lan_subnets must be CIDR prefixes")
			return
		}
		lans = append(lans, p.Masked())
	}
	res, err := h.svc.Activate(r.Context(), provision.ActivateRequest{
		Code: req.Code, PublicKey: req.PublicKey, DeviceName: req.DeviceName, OS: clip(req.OS, 64),
		ClientVersion: clip(req.ClientVersion, 32), LANSubnets: lans, RemoteIP: ip,
	})
	if err != nil {
		status, code := mapActivateErr(err)
		h.log.Warn("activation rejected", "ip", ip, "code", code)
		writeErr(w, status, code, err.Error())
		return
	}
	h.log.Info("device activated", "device", res.Device.ID, "customer", res.Device.CustomerID, "ip", ip)
	writeJSON(w, http.StatusCreated, activateResponse{DeviceToken: res.Token, Config: res.Config})
}

func mapActivateErr(err error) (int, string) {
	switch {
	case errors.Is(err, provision.ErrInvalidCode):
		return http.StatusUnauthorized, "invalid_code"
	case errors.Is(err, provision.ErrCodeUsed):
		return http.StatusConflict, "code_used"
	case errors.Is(err, provision.ErrCodeExpired):
		return http.StatusUnauthorized, "code_expired"
	case errors.Is(err, provision.ErrCodeRevoked):
		return http.StatusUnauthorized, "code_revoked"
	case errors.Is(err, provision.ErrCustomerBlocked):
		return http.StatusForbidden, "customer_blocked"
	case errors.Is(err, provision.ErrDeviceLimit):
		return http.StatusForbidden, "device_limit"
	case errors.Is(err, provision.ErrBadPublicKey):
		return http.StatusBadRequest, "bad_public_key"
	case errors.Is(err, provision.ErrDuplicateKey):
		return http.StatusConflict, "duplicate_key"
	case errors.Is(err, provision.ErrLANNotAllowed):
		return http.StatusBadRequest, "lan_not_allowed"
	case errors.Is(err, provision.ErrBlockFull):
		return http.StatusConflict, "block_full"
	case errors.Is(err, provision.ErrProvisioning):
		return http.StatusServiceUnavailable, "provisioning_failed"
	}
	if strings.HasPrefix(err.Error(), "policy:") {
		return http.StatusBadRequest, "bad_policy"
	}
	return http.StatusInternalServerError, "internal"
}

type deviceHandler func(w http.ResponseWriter, r *http.Request, d store.Device)

func (h *Handler) withDevice(next deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.deviceByIP.Allow(ip) {
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "slow down")
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "device token required")
			return
		}
		d, err := h.svc.AuthenticateDevice(r.Context(), strings.TrimSpace(auth[7:]))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "device token is not valid")
			return
		}
		next(w, r, d)
	}
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request, d store.Device) {
	cfg, err := h.svc.ConfigFor(r.Context(), d.ID)
	var denied *provision.DeniedError
	if errors.As(err, &denied) {
		writeJSON(w, http.StatusForbidden, apiError{Error: denied.Error(), Code: "access_denied", Reason: string(denied.Reason)})
		return
	}
	if err != nil {
		h.log.Error("config failed", "device", d.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not build configuration")
		return
	}
	_ = h.svc.Heartbeat(r.Context(), d.ID, clip(r.Header.Get("X-Client-Version"), 32))
	writeJSON(w, http.StatusOK, cfg)
}

type heartbeatRequest struct {
	ClientVersion string `json:"client_version"`
	Connected     bool   `json:"connected"`
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request, d store.Device) {
	var req heartbeatRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.svc.Heartbeat(r.Context(), d.ID, req.ClientVersion); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "heartbeat failed")
		return
	}
	// Re-read so the client learns about config changes and revocation.
	cfg, err := h.svc.ConfigFor(r.Context(), d.ID)
	var denied *provision.DeniedError
	if errors.As(err, &denied) {
		writeJSON(w, http.StatusForbidden, apiError{Error: denied.Error(), Code: "access_denied", Reason: string(denied.Reason)})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "heartbeat failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config_version": cfg.ConfigVersion})
}

type rotateRequest struct {
	NewPublicKey string `json:"new_public_key"`
}

func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request, d store.Device) {
	var req rotateRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.svc.RotateKey(r.Context(), d.ID, req.NewPublicKey, h.clientIP(r)); err != nil {
		status, code := http.StatusInternalServerError, "internal"
		switch {
		case errors.Is(err, provision.ErrBadPublicKey):
			status, code = http.StatusBadRequest, "bad_public_key"
		case errors.Is(err, provision.ErrDuplicateKey):
			status, code = http.StatusConflict, "duplicate_key"
		case errors.Is(err, provision.ErrDeviceRevoked):
			status, code = http.StatusForbidden, "access_denied"
		case errors.Is(err, provision.ErrProvisioning):
			status, code = http.StatusServiceUnavailable, "provisioning_failed"
		}
		writeErr(w, status, code, err.Error())
		return
	}
	cfg, err := h.svc.ConfigFor(r.Context(), d.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not build configuration")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
