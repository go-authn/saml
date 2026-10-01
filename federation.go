// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// A Federation keeps a federation's metadata fresh: it fetches it, verifies
// it, and fetches it again before it goes stale.
//
//	f := &saml.Federation{
//	    URL:  "https://pub.federation.renater.fr/metadata/fer/idps.xml",
//	    Cert: renaterCert,
//	}
//	if err := f.Refresh(ctx); err != nil { ... }
//	go f.Run(ctx, func(err error) { log.Print(err) })
//
// When a refresh fails, the last good copy stays in use -- a federation
// server being briefly unreachable must not log everybody out -- but only
// until its own validUntil. After that there is nothing left that anybody
// vouches for, and every IdP disappears.
type Federation struct {
	// URL is where the metadata is: https://, or file:// for a copy kept by
	// something else. Plain http is refused except on loopback, not
	// because the signature would not catch a change -- it would -- but
	// because somebody on the path could hold back the NEW document and
	// keep serving an old one with a revoked key until it expires.
	URL string

	// Cert is the federation's metadata signing certificate, checked once by
	// its fingerprint and kept locally.
	Cert *x509.Certificate

	// Client fetches it. A client with a two-minute timeout when
	// nil: eduGAIN's aggregate is over 50 MB.
	Client *http.Client

	// MaxSize bounds a download. 256 MB by default.
	MaxSize int64

	// MaxValidity is the longest validUntil a document may carry, from now:
	// 28 days by default (RENATER publishes about two weeks, eduGAIN five
	// days); a negative value removes the bound. A document valid for years
	// is one a replay keeps alive for years.
	MaxValidity time.Duration

	// Now is the clock. time.Now by default.
	Now func() time.Time

	mu      sync.RWMutex
	current *Metadata
	etag    string

	// refreshing serialises Refresh: two at once could each replace the
	// other's newer document with an older one.
	refreshing sync.Mutex
}

func (f *Federation) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// IdP implements IdPs, from the current metadata if it is still valid.
func (f *Federation) IdP(entityID string) (*IdP, bool) {
	md := f.Metadata()
	if md == nil {
		return nil, false
	}
	return md.IdP(entityID)
}

// Metadata is the current metadata, or nil when there is none that is still
// valid.
func (f *Federation) Metadata() *Metadata {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.current == nil || !f.now().Before(f.current.ValidUntil) {
		return nil
	}
	return f.current
}

// Refresh fetches and verifies the metadata once. A document that fails
// verification does not replace the one in use.
func (f *Federation) Refresh(ctx context.Context) error {
	f.refreshing.Lock()
	defer f.refreshing.Unlock()
	if f.Cert == nil {
		return errors.New("a federation needs its metadata signing certificate")
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return err
	}
	var data []byte
	var etag string
	switch u.Scheme {
	case "file":
		if data, err = os.ReadFile(localPath(u)); err != nil {
			return err
		}
	case "https", "http":
		if u.Scheme == "http" && !loopback(u.Hostname()) {
			return fmt.Errorf("%s: metadata over cleartext http is refused", f.URL)
		}
		if data, etag, err = f.fetch(ctx); err != nil || data == nil {
			return err // nil data: not modified since the document in use
		}
	default:
		return fmt.Errorf("%s: scheme %q", f.URL, u.Scheme)
	}
	now := f.now()
	md, err := ParseMetadata(data, f.Cert, now)
	if err != nil {
		return err
	}
	maxValidity := f.MaxValidity
	if maxValidity == 0 {
		maxValidity = 28 * 24 * time.Hour
	}
	if maxValidity > 0 && md.ValidUntil.After(now.Add(maxValidity)) {
		return fmt.Errorf("%s: valid until %s, more than %s from now", f.URL, md.ValidUntil.Format(time.RFC3339), maxValidity)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// ⛔ Never back to an older document. It is validly signed and not
	// yet expired, so nothing else refuses it -- and it may be the one with
	// the key since revoked, served by whoever stands on the path (a proxy,
	// a mirror, the writer of the file:// copy). Measured: after a newer
	// document, an older one served next replaced it without a word.
	if cur := f.current; cur != nil && md.ValidUntil.Before(cur.ValidUntil) {
		return fmt.Errorf("%s: valid until %s, older than the document in use (%s): a rollback is refused", f.URL,
			md.ValidUntil.Format(time.RFC3339), cur.ValidUntil.Format(time.RFC3339))
	}
	f.current = md
	// The ETag only now: one kept for a document that failed would make the
	// server answer 304 to every later refresh, each reported as success.
	f.etag = etag
	return nil
}

// fetch downloads the metadata and its ETag, returning nil data when the
// server says it has not changed.
func (f *Federation) fetch(ctx context.Context) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, "", err
	}
	f.mu.RLock()
	if f.etag != "" && f.current != nil {
		req.Header.Set("If-None-Match", f.etag)
	}
	f.mu.RUnlock()
	c := f.Client
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: stayHTTPS}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: %s", f.URL, resp.Status)
	}
	max := f.MaxSize
	if max == 0 {
		max = 256 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > max {
		return nil, "", fmt.Errorf("%s: larger than %d bytes", f.URL, max)
	}
	return data, resp.Header.Get("ETag"), nil
}

// Run refreshes the metadata until ctx ends: at once, then at three
// quarters of its cacheDuration, which is what Shibboleth does -- never
// more often than every five minutes nor less often than every twelve
// hours, and never past half of what remains of its validity. With no valid
// metadata it tries again within a minute, then backs off to an hour: a
// federation server down at start must not leave the SP without IdPs for
// twelve hours. errs, when not nil, is told about every failed refresh.
func (f *Federation) Run(ctx context.Context, errs func(error)) {
	retry := time.Minute
	for {
		if err := f.Refresh(ctx); err != nil && errs != nil {
			errs(err)
		}
		md := f.Metadata()
		var wait time.Duration
		if md == nil {
			wait, retry = retry, min(retry*2, time.Hour)
		} else {
			retry = time.Minute
			wait = 12 * time.Hour
			if md.CacheDuration > 0 {
				wait = md.CacheDuration * 3 / 4
			}
			wait = min(wait, md.ValidUntil.Sub(f.now())/2)
			wait = min(max(wait, 5*time.Minute), 12*time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// stayHTTPS refuses a redirect that leaves https, which Go's client follows
// by default.
func stayHTTPS(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Scheme != "https" && !loopback(req.URL.Hostname()) {
		return fmt.Errorf("a redirect to %s leaves https", req.URL.Redacted())
	}
	return nil
}

// localPath is a file:/// URL's path on this system: file:///C:/x is C:\x on
// Windows, whose paths do not start at a slash.
func localPath(u *url.URL) string {
	p := u.Path
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p)
}

func loopback(host string) bool {
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
}
