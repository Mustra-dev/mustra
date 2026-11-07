package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Whether a container image has an update, asked of the image's registry.
//
// The endpoint asks rather than the server because it can already reach the
// registries its images came from, and the server may not. It asks
// anonymously: a host's registry logins are not read, so a private image is
// reported as not checkable, never as current.
//
// A digest comparison answers "has this tag moved?", which is the whole
// question for latest. For postgres:16.4 the tag rarely moves and the real
// question is whether 16.5 exists, so version tags also list the repository.
// Manifests are read with HEAD, which Docker Hub does not count as a pull.

const (
	containerCheckBudget = 2 * time.Minute
	containerCheckers    = 4
	// Images change on a scale of days. A long interval, spread out per
	// image, keeps a large host well inside registries' rate limits.
	containerCheckEvery  = 6 * time.Hour
	containerCheckSpread = time.Hour
	containerRetryEvery  = time.Hour
	// How long a registry is left alone after it stopped answering or asked
	// for less traffic without saying how long.
	registryBackoff    = 15 * time.Minute
	registryMaxBackoff = 6 * time.Hour

	registryRequestTimeout = 20 * time.Second
	maxRegistryResponse    = 8 << 20
	maxTagPages            = 20
	tagPageSize            = 1000

	manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, " +
		"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
)

// Plain enough to be safe in a URL; anything else is not checked at all.
var (
	imageDomainRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]+)?$`)
	imageRepoRe   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._-]+|/)[a-z0-9]+)*$`)
	imageTagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// An engine shows a container's image as its ID once the tag has moved
	// on. Parsed as a name it would be a Docker Hub image nobody has.
	imageIDRe = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{12,64}$`)
)

// imageRef is a parsed image reference: docker.io/library/postgres:16.4.
type imageRef struct {
	domain string
	repo   string
	tag    string
	digest string
}

func (r imageRef) key() string { return r.domain + "/" + r.repo + ":" + r.tag }

// host is where the registry's API lives.
func (r imageRef) host() string {
	if r.domain == "docker.io" {
		return "registry-1.docker.io"
	}
	return r.domain
}

// parseImageRef follows Docker's normalisation: the first path component is
// a registry only if it could not be a Docker Hub namespace, and an image
// with no namespace is in library/.
func parseImageRef(s string) (imageRef, error) {
	var ref imageRef
	if imageIDRe.MatchString(s) {
		return ref, errors.New("an image ID, not a reference")
	}
	rest, digest, hasDigest := strings.Cut(s, "@")
	if hasDigest {
		if !imageDigestRe.MatchString(digest) {
			return ref, errors.New("unsupported digest")
		}
		ref.digest = digest
	}
	if first, after, ok := strings.Cut(rest, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		ref.domain, rest = strings.ToLower(first), after
	} else {
		ref.domain = "docker.io"
	}
	if ref.domain == "index.docker.io" {
		ref.domain = "docker.io"
	}
	// A colon in the last path component is the tag; one earlier was a port.
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		rest, ref.tag = rest[:i], rest[i+1:]
	} else {
		ref.tag = "latest"
	}
	if ref.domain == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	ref.repo = rest
	if !imageDomainRe.MatchString(ref.domain) || !imageRepoRe.MatchString(ref.repo) || !imageTagRe.MatchString(ref.tag) {
		return ref, errors.New("not a valid image reference")
	}
	return ref, nil
}

// registryResult is what a registry said about one image and tag.
type registryResult struct {
	digest       string
	newerTag     string
	newerInMajor string
	failure      string // why the tag could not be read; the rest is then empty
	tagsFailure  string // why newer tags could not be listed
	checkedAt    time.Time
	due          time.Time
}

type imageChecker struct {
	client  *http.Client
	logger  *slog.Logger
	now     func() time.Time
	running sync.Mutex // one pass at a time; a second reads what the first found

	mu      sync.Mutex
	results map[string]registryResult
	blocked map[string]time.Time // registry host -> leave alone until
}

func newImageChecker(logger *slog.Logger) *imageChecker {
	return &imageChecker{
		logger:  logger,
		now:     time.Now,
		results: map[string]registryResult{},
		blocked: map[string]time.Time{},
		client: &http.Client{
			Timeout: registryRequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme != "https" {
					return errors.New("refusing a redirect away from https")
				}
				return nil
			},
		},
	}
}

func (c *imageChecker) result(ref imageRef) (registryResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res, ok := c.results[ref.key()]
	return res, ok
}

// refresh asks about the images whose answer is due, within the budget.
// Whatever the budget does not reach keeps its previous answer and is first
// in line next time; a live query during a pass reads what is known.
func (c *imageChecker) refresh(ctx context.Context, refs []imageRef) {
	if !c.running.TryLock() {
		return
	}
	defer c.running.Unlock()
	ctx, cancel := context.WithTimeout(ctx, containerCheckBudget)
	defer cancel()

	now := c.now()
	inUse := make(map[string]bool, len(refs))
	var due []imageRef
	c.mu.Lock()
	for _, ref := range refs {
		if inUse[ref.key()] {
			continue
		}
		inUse[ref.key()] = true
		if res, ok := c.results[ref.key()]; !ok || !now.Before(res.due) {
			due = append(due, ref)
		}
	}
	for key := range c.results {
		if !inUse[key] {
			delete(c.results, key)
		}
	}
	c.mu.Unlock()

	work := make(chan imageRef)
	var wg sync.WaitGroup
	for range containerCheckers {
		wg.Go(func() {
			for ref := range work {
				c.check(ctx, ref)
			}
		})
	}
feed:
	for _, ref := range due {
		select {
		case work <- ref:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
}

func (c *imageChecker) check(ctx context.Context, ref imageRef) {
	if c.isBlocked(ref.host()) {
		return
	}
	res := c.ask(ctx, ref)
	// Cut off by the budget or by shutdown says nothing about the registry.
	if ctx.Err() != nil {
		return
	}
	res.checkedAt = c.now()
	if res.failure != "" || res.tagsFailure != "" {
		res.due = res.checkedAt.Add(containerRetryEvery)
	} else {
		res.due = res.checkedAt.Add(containerCheckEvery + rand.N(containerCheckSpread))
	}
	c.mu.Lock()
	c.results[ref.key()] = res
	c.mu.Unlock()
}

func (c *imageChecker) ask(ctx context.Context, ref imageRef) registryResult {
	session := &registrySession{checker: c, ref: ref}
	digest, err := session.manifestDigest(ctx)
	if err != nil {
		return registryResult{failure: c.describe(ref, err)}
	}
	res := registryResult{digest: digest}
	if _, ok := parseVersionTag(ref.tag); ok {
		tags, err := session.listTags(ctx)
		if err != nil {
			res.tagsFailure = "The tag is current, but newer versions could not be listed: " + c.describe(ref, err)
			return res
		}
		res.newerTag, res.newerInMajor = newerVersionTags(ref.tag, tags)
	}
	return res
}

// Docker Hub answers the same for a private image and for one it has never
// heard of, which is what a local build looks like on the containerd store.
const refusedAnonymous = "The registry refused an anonymous check: the image is private, or was built locally."

// registryError carries a sentence fit for the console. Registries' own error
// text never reaches it: it would be unbounded text from a remote host.
type registryError struct {
	detail     string
	backoff    time.Duration
	retryAfter string
}

func (e *registryError) Error() string { return e.detail }

func (c *imageChecker) describe(ref imageRef, err error) string {
	var re *registryError
	if errors.As(err, &re) {
		if re.backoff > 0 {
			c.block(ref.host(), re.backoff, re.retryAfter)
		}
		return re.detail
	}
	// Failing to connect costs a timeout per image, so one down registry
	// would spend a host's whole budget.
	c.block(ref.host(), registryBackoff, "")
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "The registry's name did not resolve from this endpoint."
	}
	return "This endpoint could not reach the registry."
}

func (c *imageChecker) isBlocked(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Before(c.blocked[host])
}

func (c *imageChecker) block(host string, d time.Duration, retryAfter string) {
	if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
		d = min(time.Duration(secs)*time.Second, registryMaxBackoff)
	}
	c.mu.Lock()
	c.blocked[host] = c.now().Add(d)
	c.mu.Unlock()
	c.logger.Info("leaving container registry alone for a while", "registry", host, "for", d)
}

// registrySession is the requests about one repository, sharing a token.
type registrySession struct {
	checker *imageChecker
	ref     imageRef
	token   string
}

func (s *registrySession) url(path string) string {
	return "https://" + s.ref.host() + "/v2/" + s.ref.repo + path
}

func (s *registrySession) do(ctx context.Context, method, target, accept string) (*http.Response, error) {
	send := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		return s.checker.client.Do(req)
	}
	resp, err := send()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && s.token == "" {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if err := s.fetchToken(ctx, challenge); err != nil {
			return nil, err
		}
		if resp, err = send(); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	return nil, statusError(resp)
}

func statusError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &registryError{detail: refusedAnonymous}
	case http.StatusNotFound:
		return &registryError{detail: "The registry does not have this tag any more."}
	case http.StatusTooManyRequests:
		return &registryError{detail: "The registry's rate limit was reached; this will retry.", backoff: registryBackoff, retryAfter: resp.Header.Get("Retry-After")}
	}
	return &registryError{detail: fmt.Sprintf("The registry answered with status %d.", resp.StatusCode)}
}

// fetchToken follows the registry's Bearer challenge. It sends no credentials
// anywhere, but the realm is the registry's to name, so it must at least be
// https and the answer is bounded like any other.
func (s *registrySession) fetchToken(ctx context.Context, challenge string) error {
	params, ok := parseBearerChallenge(challenge)
	if !ok {
		return &registryError{detail: refusedAnonymous}
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" {
		return &registryError{detail: "The registry asked for a sign-in somewhere other than https."}
	}
	q := realm.Query()
	if v := params["service"]; v != "" {
		q.Set("service", v)
	}
	q.Set("scope", "repository:"+s.ref.repo+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	resp, err := s.checker.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	var answer struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRegistryResponse)).Decode(&answer); err != nil {
		return &registryError{detail: "The registry's sign-in service gave an unreadable answer."}
	}
	s.token = answer.Token
	if s.token == "" {
		s.token = answer.AccessToken
	}
	if s.token == "" {
		return &registryError{detail: refusedAnonymous}
	}
	return nil
}

// parseBearerChallenge reads: Bearer realm="https://...",service="...",scope="..."
func parseBearerChallenge(h string) (map[string]string, bool) {
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	params := map[string]string{}
	for _, m := range bearerParamRe.FindAllStringSubmatch(rest, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	return params, params["realm"] != ""
}

var bearerParamRe = regexp.MustCompile(`([A-Za-z]+)="([^"]*)"`)

func (s *registrySession) manifestDigest(ctx context.Context) (string, error) {
	target := s.url("/manifests/" + s.ref.tag)
	resp, err := s.do(ctx, http.MethodHead, target, manifestAccept)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if d := resp.Header.Get("Docker-Content-Digest"); imageDigestRe.MatchString(d) {
		return d, nil
	}
	// The header is optional. A digest is the hash of the manifest, so the
	// body gives the same answer at the cost of a counted pull.
	if resp, err = s.do(ctx, http.MethodGet, target, manifestAccept); err != nil {
		return "", err
	}
	defer resp.Body.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, maxRegistryResponse)); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// listTags reads up to maxTagPages pages. Repositories list tags in lexical
// order, so the bound could miss a newer tag only past 20,000 of them.
func (s *registrySession) listTags(ctx context.Context) ([]string, error) {
	base, err := url.Parse(s.url("/tags/list?n=" + strconv.Itoa(tagPageSize)))
	if err != nil {
		return nil, err
	}
	var tags []string
	next := base
	for range maxTagPages {
		page, link, err := s.tagPage(ctx, next.String())
		if err != nil {
			return nil, err
		}
		tags = append(tags, page...)
		target := nextLink(link)
		if target == "" {
			break
		}
		u, err := next.Parse(target)
		if err != nil || u.Host != base.Host || u.Scheme != "https" {
			break
		}
		next = u
	}
	return tags, nil
}

func (s *registrySession) tagPage(ctx context.Context, target string) ([]string, string, error) {
	resp, err := s.do(ctx, http.MethodGet, target, "")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var page struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRegistryResponse)).Decode(&page); err != nil {
		return nil, "", &registryError{detail: "The registry's list of tags was not readable."}
	}
	return page.Tags, resp.Header.Get("Link"), nil
}

func nextLink(h string) string {
	for part := range strings.SplitSeq(h, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		target = strings.TrimSpace(target)
		if strings.HasPrefix(target, "<") && strings.HasSuffix(target, ">") {
			return target[1 : len(target)-1]
		}
	}
	return ""
}

// versionTag is a tag that reads as a version: v1.2.3, 16, 16.4-alpine.
type versionTag struct {
	prefix string
	nums   []int64
	first  string // the first number as written, for its length
	suffix string
}

var versionTagRe = regexp.MustCompile(`^(v?)([0-9]+(?:\.[0-9]+)*)(-[A-Za-z0-9._-]+)?$`)

func parseVersionTag(tag string) (versionTag, bool) {
	m := versionTagRe.FindStringSubmatch(tag)
	if m == nil {
		return versionTag{}, false
	}
	parts := strings.Split(m[2], ".")
	v := versionTag{prefix: m[1], suffix: m[3], first: parts[0]}
	for _, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return versionTag{}, false
		}
		v.nums = append(v.nums, n)
	}
	return v, true
}

// sameShape keeps comparisons to tags a person on the current one would
// treat as its successors. 16.4-alpine is not followed by 17 (another
// variant) or by 16.5.1-alpine (another precision); a plain 16 is not
// followed by a date-stamped 20240101 in the same repository.
func (v versionTag) sameShape(o versionTag) bool {
	return v.prefix == o.prefix && v.suffix == o.suffix && len(v.nums) == len(o.nums) && len(o.first) <= len(v.first)+1
}

func (v versionTag) newerThan(o versionTag) bool {
	for i := range v.nums {
		if v.nums[i] != o.nums[i] {
			return v.nums[i] > o.nums[i]
		}
	}
	return false
}

// newerVersionTags finds the highest tag of the same shape as current, and
// the highest with the same first number when that is a different tag.
func newerVersionTags(current string, tags []string) (newest, inMajor string) {
	cur, ok := parseVersionTag(current)
	if !ok {
		return "", ""
	}
	best, bestMajor := cur, cur
	for _, t := range tags {
		v, ok := parseVersionTag(t)
		if !ok || !cur.sameShape(v) || !v.newerThan(cur) {
			continue
		}
		if v.newerThan(best) {
			best, newest = v, t
		}
		if len(cur.nums) > 1 && v.nums[0] == cur.nums[0] && v.newerThan(bestMajor) {
			bestMajor, inMajor = v, t
		}
	}
	if inMajor == newest {
		inMajor = ""
	}
	return newest, inMajor
}
