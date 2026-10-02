package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestClientLatestAndDownload(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "DishNetSecureConnect-Setup.exe")
	body := []byte("MZ fake 0.2.2")
	os.WriteFile(exe, body, 0o644)
	os.WriteFile(filepath.Join(dir, "VERSION"), []byte("client-v0.2.2\n"), 0o644)
	mux := http.NewServeMux()
	NewUpdates(exe, "https://vpn.test/").Register(mux)
	srv := newTestServer(t, mux)

	res, err := http.Get(srv.URL + "/api/v1/client/latest")
	if err != nil {
		t.Fatal(err)
	}
	var info latestInfo
	json.NewDecoder(res.Body).Decode(&info)
	want := sha256.Sum256(body)
	if info.Version != "0.2.2" || info.URL != "https://vpn.test/download/DishNetSecureConnect-Setup.exe" || info.SHA256 != hex.EncodeToString(want[:]) || info.Size != int64(len(body)) {
		t.Fatalf("latest: %+v", info)
	}
	dl, _ := http.Get(info.URL[len("https://vpn.test"):][0:0] + srv.URL + "/download/DishNetSecureConnect-Setup.exe")
	if dl.StatusCode != 200 || dl.Header.Get("Content-Disposition") != `attachment; filename="DishNetSecureConnect-Setup.exe"` {
		t.Fatalf("download: %d %s", dl.StatusCode, dl.Header.Get("Content-Disposition"))
	}
	// No installer cached -> 404 with a code the app understands.
	os.Remove(exe)
	nf, _ := http.Get(srv.URL + "/api/v1/client/latest")
	if nf.StatusCode != 404 {
		t.Fatalf("missing installer: %d", nf.StatusCode)
	}
}
