package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Containers: what the host's container engine runs, read from its API over
// its local socket, and whether each image has an update (container_updates.go).
//
// The socket rather than the docker command, so a host needs no CLI, and only
// GET requests: this sensor reports and never changes anything. Windows and
// rootless engines have no socket at these paths and report no containers.
var containerSockets = []string{"/var/run/docker.sock", "/run/podman/podman.sock"}

const (
	// Bounds the snapshot on a host that runs an unusual number of
	// containers, or has kept every exited one.
	maxContainersReported = 1000
	maxEngineResponse     = 16 << 20
	maxContainerField     = 512
)

type containerCollector struct {
	sockets []string
	checker *imageChecker // nil when update checks are turned off
	logger  *slog.Logger
}

func newContainerCollector(checkUpdates bool, logger *slog.Logger) *containerCollector {
	c := &containerCollector{sockets: containerSockets, logger: logger}
	if checkUpdates {
		c.checker = newImageChecker(logger)
	}
	return c
}

// collect reports the first engine that answers. An engine whose socket
// exists but does not answer is an error, not an empty list, so the server
// keeps the last snapshot rather than showing the containers as gone.
func (c *containerCollector) collect(ctx context.Context) ([]proto.ContainerInfo, error) {
	var lastErr error
	for _, sock := range c.sockets {
		if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
			continue
		}
		seen, err := readEngine(ctx, newEngineClient(sock))
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", sock, err)
			continue
		}
		return c.rate(ctx, seen), nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return []proto.ContainerInfo{}, nil
}

// seenContainer is a container and its image's digests at the registry.
type seenContainer struct {
	info    proto.ContainerInfo
	digests []string // repo@sha256:... as the engine lists them
}

// rate asks the registries about every image in use, then concludes per
// container: two containers of one tag can be running different images.
func (c *containerCollector) rate(ctx context.Context, seen []seenContainer) []proto.ContainerInfo {
	if c.checker != nil {
		refs := make([]imageRef, 0, len(seen))
		for _, s := range seen {
			if ref, err := parseImageRef(s.info.Image); err == nil && ref.digest == "" {
				refs = append(refs, ref)
			}
		}
		c.checker.refresh(ctx, refs)
	}
	out := make([]proto.ContainerInfo, 0, len(seen))
	for _, s := range seen {
		info := s.info
		rateContainer(&info, s.digests, c.checker)
		out = append(out, info)
	}
	return out
}

func rateContainer(info *proto.ContainerInfo, digests []string, checker *imageChecker) {
	info.Update = proto.ContainerNotChecked
	ref, err := parseImageRef(info.Image)
	if err != nil {
		info.UpdateDetail = "The image has no name a registry could be asked about."
		return
	}
	if ref.digest != "" {
		info.UpdateDetail = "Pinned by digest, so it does not change until the reference does."
		return
	}
	running := digestsInRepo(ref, digests)
	if len(running) > 0 {
		info.ImageDigest = running[0]
	}
	if len(running) == 0 {
		info.UpdateDetail = "Built or loaded on this host, so there is no registry digest to compare."
		return
	}
	if checker == nil {
		info.UpdateDetail = "Update checks are turned off on this agent."
		return
	}
	res, ok := checker.result(ref)
	if !ok {
		info.UpdateDetail = "Not checked yet."
		return
	}
	info.CheckedAt = res.checkedAt.UTC().Format(time.RFC3339)
	if res.failure != "" {
		info.Update, info.UpdateDetail = proto.ContainerCheckFailed, res.failure
		return
	}
	info.LatestDigest, info.NewerTag, info.NewerTagInMajor = res.digest, res.newerTag, res.newerInMajor
	moved := !slices.Contains(running, res.digest)
	switch {
	case moved && res.newerTag != "":
		info.Update = proto.ContainerUpdateAvailable
		info.UpdateDetail = "This tag now points to a different image, and a newer version tag exists."
	case moved:
		info.Update = proto.ContainerUpdateAvailable
		info.UpdateDetail = "This tag now points to a different image."
	case res.newerTag != "":
		info.Update = proto.ContainerUpdateAvailable
		info.UpdateDetail = "A newer version tag exists."
	case res.tagsFailure != "":
		// The digest matches, but a pinned version's real question is
		// whether a newer tag exists, and that went unanswered.
		info.Update, info.UpdateDetail = proto.ContainerCheckFailed, res.tagsFailure
	default:
		info.Update = proto.ContainerUpToDate
	}
}

// digestsInRepo keeps the digests from the image's own repository: an image
// tagged myapp:prod from a pull of nginx has only nginx's, which say nothing
// about myapp.
func digestsInRepo(ref imageRef, repoDigests []string) []string {
	var out []string
	for _, d := range repoDigests {
		r, err := parseImageRef(d)
		if err == nil && r.digest != "" && r.domain == ref.domain && r.repo == ref.repo {
			out = append(out, r.digest)
		}
	}
	return out
}

func newEngineClient(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
}

type engineContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
}

func readEngine(ctx context.Context, client *http.Client) ([]seenContainer, error) {
	defer client.CloseIdleConnections()
	var listed []engineContainer
	if err := engineGet(ctx, client, "/containers/json?all=1", &listed); err != nil {
		return nil, err
	}
	// Running ones first, so the bound drops the exited ones.
	slices.SortStableFunc(listed, func(a, b engineContainer) int {
		if ar, br := a.State == "running", b.State == "running"; ar != br {
			if ar {
				return -1
			}
			return 1
		}
		return cmp.Compare(containerName(a), containerName(b))
	})
	if len(listed) > maxContainersReported {
		listed = listed[:maxContainersReported]
	}
	digestsByImage := map[string][]string{}
	out := make([]seenContainer, 0, len(listed))
	for _, l := range listed {
		digests, known := digestsByImage[l.ImageID]
		if !known && l.ImageID != "" {
			var image struct {
				RepoDigests []string `json:"RepoDigests"`
			}
			// A failure leaves no digests, which reports the container as
			// not checked rather than guessing.
			if err := engineGet(ctx, client, "/images/"+url.PathEscape(l.ImageID)+"/json", &image); err == nil {
				digests = image.RepoDigests
			}
			digestsByImage[l.ImageID] = digests
		}
		out = append(out, seenContainer{digests: digests, info: proto.ContainerInfo{
			ID:             truncateID(l.ID),
			Name:           boundField(containerName(l)),
			Image:          boundField(configuredImage(ctx, client, l)),
			State:          boundField(l.State),
			Status:         boundField(l.Status),
			ComposeProject: boundField(l.Labels["com.docker.compose.project"]),
			ComposeService: boundField(l.Labels["com.docker.compose.service"]),
			ComposeFile:    boundField(l.Labels["com.docker.compose.project.config_files"]),
		}})
	}
	return out, nil
}

// configuredImage is the reference the container was created from. Once its
// tag has moved to a newer pull, the list shows the old image's ID instead,
// and that container is exactly the one that needs its tag known.
func configuredImage(ctx context.Context, client *http.Client, l engineContainer) string {
	if !imageIDRe.MatchString(l.Image) {
		return l.Image
	}
	var inspected struct {
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	if err := engineGet(ctx, client, "/containers/"+url.PathEscape(l.ID)+"/json", &inspected); err != nil || inspected.Config.Image == "" {
		return l.Image
	}
	return inspected.Config.Image
}

func engineGet(ctx context.Context, client *http.Client, path string, into any) error {
	// The host is ignored: the transport always dials the socket.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("container engine answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxEngineResponse)).Decode(into); err != nil {
		return errors.Join(errors.New("container engine answer not readable"), err)
	}
	return nil
}

func containerName(l engineContainer) string {
	if len(l.Names) == 0 {
		return truncateID(l.ID)
	}
	return strings.TrimPrefix(l.Names[0], "/")
}

func truncateID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func boundField(s string) string {
	if len(s) > maxContainerField {
		return strings.ToValidUTF8(s[:maxContainerField], "")
	}
	return s
}
