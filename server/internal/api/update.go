package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dishnetafrica/wiregaurd/server/internal/ratelimit"
)

// Client self-update: GET /api/v1/client/latest tells the app which version
// the hub carries; GET /download/DishNetSecureConnect-Setup.exe serves it
// (no activation code — upgrades keep the existing identity). The version
// comes from the VERSION file written by deploy/fetch-installer.sh.
type Updates struct {
	installer string
	publicURL string
	byIP      *ratelimit.Limiter
	mu        sync.Mutex
	cached    latestInfo
	cachedAt  time.Time
	cachedMod time.Time
}

type latestInfo struct {
	Version string `json:"version"` // e.g. "0.2.2"
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

func NewUpdates(installerPath, publicURL string) *Updates {
	return &Updates{installer: installerPath, publicURL: strings.TrimRight(publicURL, "/"), byIP: ratelimit.New(30, 10*time.Minute)}
}

func (u *Updates) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/client/latest", u.latest)
	mux.HandleFunc("GET /download/DishNetSecureConnect-Setup.exe", u.download)
}

func (u *Updates) info() (latestInfo, bool) {
	st, err := os.Stat(u.installer)
	if err != nil {
		return latestInfo{}, false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cached.Version != "" && u.cachedMod.Equal(st.ModTime()) && time.Since(u.cachedAt) < time.Minute {
		return u.cached, true
	}
	dir := filepath.Dir(u.installer)
	ver, _ := os.ReadFile(filepath.Join(dir, "VERSION"))
	version := strings.TrimPrefix(strings.TrimSpace(string(ver)), "client-v")
	if version == "" {
		return latestInfo{}, false
	}
	sum, _ := os.ReadFile(filepath.Join(dir, "SHA256"))
	sha := strings.TrimSpace(string(sum))
	if len(sha) != 64 {
		f, err := os.Open(u.installer)
		if err != nil {
			return latestInfo{}, false
		}
		h := sha256.New()
		_, _ = io.Copy(h, f)
		f.Close()
		sha = hex.EncodeToString(h.Sum(nil))
	}
	u.cached = latestInfo{Version: version, URL: u.publicURL + "/download/DishNetSecureConnect-Setup.exe", SHA256: sha, Size: st.Size()}
	u.cachedAt, u.cachedMod = time.Now(), st.ModTime()
	return u.cached, true
}

func (u *Updates) latest(w http.ResponseWriter, r *http.Request) {
	info, ok := u.info()
	if !ok {
		writeErr(w, http.StatusNotFound, "no_installer", "no client build is published on this hub")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (u *Updates) download(w http.ResponseWriter, r *http.Request) {
	if !u.byIP.Allow(clientIPOf(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "slow down")
		return
	}
	f, err := os.Open(u.installer)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no_installer", "no client build is published on this hub")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="DishNetSecureConnect-Setup.exe"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "DishNetSecureConnect-Setup.exe", st.ModTime(), f)
}
