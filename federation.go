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

	// Now is the clock. time.Now by default.
	Now func() time.Time

	mu      sync.RWMutex
	current *Metadata
	etag    string
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
	if f.Cert == nil {
		return errors.New("a federation needs its metadata signing certificate")
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return err
	}
	var data []byte
	switch u.Scheme {
	case "file":
		if data, err = os.ReadFile(localPath(u)); err != nil {
			return err
		}
	case "https", "http":
		if u.Scheme == "http" && !loopback(u.Hostname()) {
			return fmt.Errorf("%s: metadata over cleartext http is refused", f.URL)
		}
		if data, err = f.fetch(ctx); err != nil || data == nil {
			return err
		}
	default:
		return fmt.Errorf("%s: scheme %q", f.URL, u.Scheme)
	}
	md, err := ParseMetadata(data, f.Cert, f.now())
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.current = md
	f.mu.Unlock()
	return nil
}

// fetch downloads the metadata, returning nil data when the server says it
// has not changed.
func (f *Federation) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	f.mu.RLock()
	if f.etag != "" && f.current != nil {
		req.Header.Set("If-None-Match", f.etag)
	}
	f.mu.RUnlock()
	c := f.Client
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", f.URL, resp.Status)
	}
	max := f.MaxSize
	if max == 0 {
		max = 256 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", f.URL, max)
	}
	f.mu.Lock()
	f.etag = resp.Header.Get("ETag")
	f.mu.Unlock()
	return data, nil
}

// Run refreshes the metadata until ctx ends: at three quarters of its
// cacheDuration, which is what Shibboleth does, but never more often than
// every five minutes nor less often than every twelve hours. errs, when not
// nil, is told about every failed refresh.
func (f *Federation) Run(ctx context.Context, errs func(error)) {
	for {
		wait := 12 * time.Hour
		if md := f.Metadata(); md != nil && md.CacheDuration > 0 {
			wait = md.CacheDuration * 3 / 4
		}
		wait = min(max(wait, 5*time.Minute), 12*time.Hour)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := f.Refresh(ctx); err != nil && errs != nil {
			errs(err)
		}
	}
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
