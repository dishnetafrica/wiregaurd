package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestManualIsServedAndCleanOfInternals(t *testing.T) {
	mux := http.NewServeMux()
	RegisterManual(mux)
	srv := newTestServer(t, mux)
	res, err := http.Get(srv.URL + "/guide")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("guide: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	html := string(body)
	for _, want := range []string{"Customer Setup Guide", "Remote Desktop", "Windows Home cannot accept", "Tally runs on the office computer"} {
		if !strings.Contains(html, want) {
			t.Fatalf("manual missing %q", want)
		}
	}
	for _, forbidden := range []string{"10.20.", "wg0", "dnd_", "nftables", "51820", "PrivateKey"} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("manual leaks %q", forbidden)
		}
	}
	pdf, _ := http.Get(srv.URL + "/guide.pdf")
	pb, _ := io.ReadAll(pdf.Body)
	if pdf.StatusCode != 200 || pdf.Header.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(string(pb[:4]), "%PDF") {
		t.Fatalf("pdf: %d %s", pdf.StatusCode, pdf.Header.Get("Content-Type"))
	}
}
