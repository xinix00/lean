package leans3

// Object operations map one object to one request. Multipart, retries, and
// orchestration policy belong above this layer.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/xinix00/lean/leanhttp"
)

const maxBufferedGetBytes int64 = 4 << 20

// PutOptions contains one PUT's conditions and metadata. Nil means an
// unconditional application/octet-stream write. IfMatch and IfNoneMatch are raw
// header values because providers disagree about quoted ETag forms.
type PutOptions struct {
	// ContentType defaults to "application/octet-stream".
	ContentType string

	// IfMatch writes only when the stored ETag matches.
	IfMatch string

	// IfNoneMatch writes only when it does not match. "*" creates only when the
	// object does not exist, supporting CAS protocols.
	IfNoneMatch string
}

// DeleteOptions contains one DELETE's condition. Nil means unconditional.
type DeleteOptions struct {
	// IfMatch deletes only when the stored ETag matches.
	IfMatch string
}

// Get returns an object's bytes and ETag, or [ErrNotFound]. It buffers at most
// 4 MiB; use [Client.GetTo] for larger objects.
func (c *Client) Get(ctx context.Context, key string) ([]byte, string, error) {
	u, err := c.URLFor(key)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.do(ctx, request{
		op: methodGet, key: key, method: methodGet, url: u,
		payloadHash: emptyPayloadHash,
	})
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != leanhttp.StatusOK {
		return nil, "", c.fail(methodGet, key, resp)
	}
	if resp.Length > maxBufferedGetBytes {
		return nil, "", fmt.Errorf("%w: GET %s is %d bytes; limit is %d",
			ErrObjectTooLarge, key, resp.Length, maxBufferedGetBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBufferedGetBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("leans3: read GET %s body: %w", key, err)
	}
	if int64(len(data)) > maxBufferedGetBytes {
		return nil, "", fmt.Errorf("%w: GET %s exceeds %d bytes",
			ErrObjectTooLarge, key, maxBufferedGetBytes)
	}
	return data, resp.Header.Get("ETag"), nil
}

// GetTo streams an object to w and returns its byte count and ETag. An absent
// key returns [ErrNotFound] before writing. Writer errors remain unwrap-able so
// callers can distinguish local storage failures from transport failures.
func (c *Client) GetTo(ctx context.Context, key string, w io.Writer) (int64, string, error) {
	u, err := c.URLFor(key)
	if err != nil {
		return 0, "", err
	}
	resp, err := c.do(ctx, request{
		op: methodGet, key: key, method: methodGet, url: u,
		payloadHash: emptyPayloadHash,
	})
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != leanhttp.StatusOK {
		return 0, "", c.fail(methodGet, key, resp)
	}
	etag := resp.Header.Get("ETag")
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return n, etag, fmt.Errorf("leans3: stream GET %s body: %w", key, err)
	}
	return n, etag, nil
}

// Put writes data to key and returns the server's ETag, or "" when absent. It
// computes the payload hash without another body copy. Failed conditions return
// [ErrPreconditionFailed] without writing.
func (c *Client) Put(ctx context.Context, key string, data []byte, opt *PutOptions) (string, error) {
	u, err := c.URLFor(key)
	if err != nil {
		return "", err
	}
	// S3 requires Content-Length: 0 for empty PUT; a non-nil empty slice makes
	// leanhttp emit it.
	if data == nil {
		data = []byte{}
	}
	resp, err := c.do(ctx, request{
		op: methodPut, key: key, method: methodPut, url: u,
		header:      putHeader(opt),
		body:        data,
		payloadHash: hexSHA256(data),
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case leanhttp.StatusOK, leanhttp.StatusCreated, leanhttp.StatusNoContent:
		// Draining proves the body complete and returns the connection to the pool.
		// Error handling below needs its body first.
		io.Copy(io.Discard, resp.Body)
		return resp.Header.Get("ETag"), nil
	default:
		return "", c.fail(methodPut, key, resp)
	}
}

// PutFrom streams exactly size bytes from r and returns the ETag without
// buffering the payload. payloadSHA256 is the lowercase hash supplied by the
// source owner; use [UnsignedPayload] only for a non-replayable source. Empty is
// rejected rather than silently weakening integrity. A length mismatch fails in
// leanhttp and a content mismatch fails at S3 as BadDigest.
func (c *Client) PutFrom(ctx context.Context, key string, r io.Reader, size int64, payloadSHA256 string, opt *PutOptions) (string, error) {
	if payloadSHA256 == "" {
		return "", errors.New("leans3: PutFrom needs the payload's sha256 " +
			"(it cannot be computed without buffering the object) — pass leans3.UnsignedPayload if the source cannot be read twice")
	}
	if size < 0 {
		return "", fmt.Errorf("leans3: PutFrom needs the size up front, got %d", size)
	}
	if payloadSHA256 == UnsignedPayload && !strings.HasPrefix(strings.ToLower(c.Endpoint), "https://") {
		// An unsigned, unencrypted payload is silently modifiable in transit.
		return "", errors.New("leans3: UnsignedPayload over a plain-http endpoint would be silently modifiable in transit — use https, or pass the payload's sha256")
	}
	u, err := c.URLFor(key)
	if err != nil {
		return "", err
	}
	if size == 0 {
		// Zero bytes use the regular Content-Length: 0 path without an unnecessary
		// Expect exchange. S3 still verifies the caller's hash.
		resp, err := c.do(ctx, request{
			op: methodPut, key: key, method: methodPut, url: u,
			header:      putHeader(opt),
			body:        []byte{},
			payloadHash: payloadSHA256,
		})
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case leanhttp.StatusOK, leanhttp.StatusCreated, leanhttp.StatusNoContent:
			io.Copy(io.Discard, resp.Body) // Drain for reuse; see Put.
			return resp.Header.Get("ETag"), nil
		default:
			return "", c.fail(methodPut, key, resp)
		}
	}
	// BodyReader plus BodyLen sends a known-length stream. Without the length,
	// S3 requires chunking and a streaming signature, both outside scope.
	resp, err := c.do(ctx, request{
		op: methodPut, key: key, method: methodPut, url: u,
		header:      putHeader(opt),
		stream:      r,
		streamLen:   size,
		payloadHash: payloadSHA256,
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case leanhttp.StatusOK, leanhttp.StatusCreated, leanhttp.StatusNoContent:
		io.Copy(io.Discard, resp.Body) // Drain for reuse; see Put.
		return resp.Header.Get("ETag"), nil
	default:
		return "", c.fail(methodPut, key, resp)
	}
}

// Delete removes key. Missing objects return [ErrNotFound], which idempotent
// callers may ignore with errors.Is. A failed IfMatch returns
// [ErrPreconditionFailed].
func (c *Client) Delete(ctx context.Context, key string, opt *DeleteOptions) error {
	u, err := c.URLFor(key)
	if err != nil {
		return err
	}
	hdr := leanhttp.Header{}
	if opt != nil && opt.IfMatch != "" {
		hdr.Set("If-Match", opt.IfMatch)
	}
	resp, err := c.do(ctx, request{
		op: methodDelete, key: key, method: methodDelete, url: u,
		header:      hdr,
		payloadHash: emptyPayloadHash,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case leanhttp.StatusOK, leanhttp.StatusNoContent:
		io.Copy(io.Discard, resp.Body) // Drain for reuse; see Put.
		return nil
	default:
		return c.fail(methodDelete, key, resp)
	}
}

// putHeader sets PUT content type and conditions. leanhttp owns Content-Length,
// which canonicalRequest deliberately does not sign.
func putHeader(opt *PutOptions) leanhttp.Header {
	contentType := "application/octet-stream"
	hdr := leanhttp.Header{}
	if opt != nil {
		if opt.ContentType != "" {
			contentType = opt.ContentType
		}
		if opt.IfMatch != "" {
			hdr.Set("If-Match", opt.IfMatch)
		}
		if opt.IfNoneMatch != "" {
			hdr.Set("If-None-Match", opt.IfNoneMatch)
		}
	}
	hdr.Set("Content-Type", contentType)
	return hdr
}

// listBucketResult is the ListObjectsV2 subset extracted by listparse.go. It
// matches local element names independently of namespace.
type listBucketResult struct {
	IsTruncated           bool
	NextContinuationToken string
	Contents              []listEntry
}

// listEntry is one page object. [Client.List] explains why only its key remains.
type listEntry struct {
	Key string
}

// List returns keys with prefix in S3 lexical order and follows pagination.
// max must be positive and bounds the returned slice. The result sets truncated
// when max is reached. Sizes and dates are omitted because current consumers need
// only a key map.
func (c *Client) List(ctx context.Context, prefix string, max int) (keys []string, truncated bool, err error) {
	if max <= 0 {
		return nil, false, errors.New("leans3: List max must be positive")
	}
	token := ""
	for {
		page, err := c.listPage(ctx, prefix, token)
		if err != nil {
			return nil, false, err
		}
		for _, item := range page.Contents {
			if len(keys) >= max {
				return keys, true, nil
			}
			keys = append(keys, item.Key)
		}
		if len(keys) == max && page.IsTruncated {
			return keys, true, nil
		}
		if !page.IsTruncated {
			return keys, false, nil
		}
		if page.NextContinuationToken == "" {
			return nil, false, fmt.Errorf("leans3: LIST %s: truncated page without a continuation token", prefix)
		}
		if len(page.Contents) == 0 {
			return nil, false, fmt.Errorf("leans3: LIST %s: truncated page made no key progress", prefix)
		}
		next := page.NextContinuationToken
		if next == token {
			return nil, false, fmt.Errorf("leans3: LIST %s: continuation token did not advance", prefix)
		}
		token = next
	}
}

// listPage fetches one ListObjectsV2 page.
func (c *Client) listPage(ctx context.Context, prefix, token string) (*listBucketResult, error) {
	u, err := c.bucketURL()
	if err != nil {
		return nil, err
	}
	q := url.Values{"list-type": {"2"}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if token != "" {
		q.Set("continuation-token", token)
	}
	u.RawQuery = q.Encode()

	resp, err := c.do(ctx, request{
		op: "LIST", key: prefix, method: methodGet, url: u,
		payloadHash: emptyPayloadHash,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != leanhttp.StatusOK {
		return nil, c.fail("LIST", prefix, resp)
	}
	// A valid page has at most 1,000 keys of at most 1 KiB. Bound reads before
	// parsing so a stalled or hostile response cannot grow the heap indefinitely.
	const maxPage = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPage+1))
	if err != nil {
		return nil, fmt.Errorf("leans3: read LIST %s body: %w", prefix, err)
	}
	if len(body) > maxPage {
		return nil, fmt.Errorf("leans3: LIST %s response exceeds %d bytes", prefix, maxPage)
	}
	page, err := parseListPage(body)
	if err != nil {
		return nil, fmt.Errorf("parse LIST %s response: %w", prefix, err)
	}
	return page, nil
}
