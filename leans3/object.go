package leans3

// De objectoperaties. Eén object is één verzoek: geen multipart, geen retries,
// geen beleid — wie een lease of een orkestrator bouwt, bouwt dat erbovenop.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/xinix00/lean/leanhttp"
)

// PutOptions zijn de voorwaarde en de metadata van één PUT. nil = onvoorwaardelijk
// schrijven met "application/octet-stream".
//
// IfMatch en IfNoneMatch zijn de RUWE headerwaarden, niet een vriendelijker
// vorm ("alleen aanmaken", "vervang versie X"). Dat is opzet: providers zijn
// het oneens over de vorm van een ETag — sommige geven hem met dubbele
// aanhalingstekens terug en vergelijken hem zonder — en wie dat moet omzeilen,
// moet exact kunnen zeggen wat er op de draad staat.
type PutOptions struct {
	// ContentType is de Content-Type van het object; leeg =
	// "application/octet-stream".
	ContentType string

	// IfMatch schrijft alleen als de opgeslagen ETag dit is.
	IfMatch string

	// IfNoneMatch schrijft alleen als hij NIET matcht; "*" betekent "alleen als
	// het object nog niet bestaat" — dat is de conditionele create waar een
	// CAS-protocol op staat.
	IfNoneMatch string
}

// DeleteOptions is de voorwaarde van één DELETE. nil = onvoorwaardelijk.
type DeleteOptions struct {
	// IfMatch verwijdert alleen als de opgeslagen ETag dit is.
	IfMatch string
}

// Get haalt het object op en geeft de bytes plus zijn ETag. Een key die niet
// bestaat geeft [ErrNotFound].
//
// Voor iets groters dan een configuratie of een staat-snapshot: [Client.GetTo].
// Deze vorm houdt het hele object in het geheugen, en op een node met 64MB is
// dat het verschil tussen werken en een OOM.
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("leans3: read GET %s body: %w", key, err)
	}
	return data, resp.Header.Get("ETag"), nil
}

// GetTo streamt het object naar w en geeft het aantal geschreven bytes plus de
// ETag. Een key die niet bestaat geeft [ErrNotFound], en dan is er niets naar w
// geschreven.
//
// Een schrijffout van w breekt de download af en komt ONGEWIKKELD terug (via
// %w te ontrafelen), zodat een aanroeper zijn eigen volle schijf van een
// transportstoring kan onderscheiden.
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

// Put schrijft data naar key en geeft de ETag die de server teruggaf ("" als hij
// er geen stuurde). De payload-hash wordt hier berekend — de body zit al in het
// geheugen, dus dat kost één pass en geen tweede kopie.
//
// Met een voorwaarde in opt die niet gold: [ErrPreconditionFailed], en dan is er
// niets geschreven.
func (c *Client) Put(ctx context.Context, key string, data []byte, opt *PutOptions) (string, error) {
	u, err := c.URLFor(key)
	if err != nil {
		return "", err
	}
	// Een leeg object moet nog steeds Content-Length: 0 aankondigen — S3
	// antwoordt 411 op een PUT zonder — en leanhttp schrijft die header alleen
	// voor een body die niet nil is.
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
		// Leegdrinken is wat de verbinding aan de pool teruggeeft: leanhttp
		// hergebruikt alleen een body die tot het einde gelezen is. Niet vóór
		// de switch — de foutweg heeft die bytes nodig.
		io.Copy(io.Discard, resp.Body)
		return resp.Header.Get("ETag"), nil
	default:
		return "", c.fail(methodPut, key, resp)
	}
}

// PutFrom streamt precies size bytes uit r naar key, zonder de payload in het
// geheugen te houden, en geeft de ETag terug.
//
// payloadSHA256 is de lowercase hex-sha256 van die bytes: SigV4 signeert de
// payload-hash, en bij een stroom kan dit pakket hem niet berekenen zonder
// alles te bufferen — dus komt hij van de aanroeper, die de bron bezit
// (meestal een goedkope eerste pass over een lokaal bestand). Een bron die niet
// twee keer te lezen is, kan [UnsignedPayload] meegeven; leeg is een FOUT en
// geen stille keuze, want stil UNSIGNED-PAYLOAD sturen is precies het soort
// verzwakking dat niemand terugvindt.
//
// Levert r een ander aantal bytes, dan faalt het verzoek luid (leanhttp
// vergelijkt met BodyLen); levert hij andere inhoud, dan wijst S3 hem af
// (BadDigest). Een gescheurde bron is dus nooit een stil beschadigd object.
func (c *Client) PutFrom(ctx context.Context, key string, r io.Reader, size int64, payloadSHA256 string, opt *PutOptions) (string, error) {
	if payloadSHA256 == "" {
		return "", errors.New("leans3: PutFrom needs the payload's sha256 " +
			"(it cannot be computed without buffering the object) — pass leans3.UnsignedPayload if the source cannot be read twice")
	}
	if size < 0 {
		return "", fmt.Errorf("leans3: PutFrom needs the size up front, got %d", size)
	}
	u, err := c.URLFor(key)
	if err != nil {
		return "", err
	}
	// BodyReader plus BodyLen stuurt de payload als stroom mét een
	// Content-Length. Die lengte is geen netheid: zonder hem zou het verzoek
	// gechunkt moeten worden, en S3 accepteert een gechunkte upload alleen met
	// een streaming signature — die dit pakket bewust niet heeft.
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
		io.Copy(io.Discard, resp.Body) // leegdrinken: zie Put
		return resp.Header.Get("ETag"), nil
	default:
		return "", c.fail(methodPut, key, resp)
	}
}

// Delete verwijdert key. Een object dat er niet is geeft [ErrNotFound]; wie een
// idempotente delete wil, negeert die met errors.Is.
//
// Met een IfMatch die niet gold: [ErrPreconditionFailed].
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
		io.Copy(io.Discard, resp.Body) // leegdrinken: zie Put
		return nil
	default:
		return c.fail(methodDelete, key, resp)
	}
}

// putHeader zet de Content-Type en de voorwaarde van een PUT. Content-Length
// staat er bewust niet in: die schrijft leanhttp, en de signatuur dekt hem niet
// (zie canonicalRequest).
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

// listBucketResult is het deel van het ListObjectsV2-antwoord dat dit pakket
// leest; listparse.go haalt het uit de XML. De namespace van het S3-document
// hoeft geen aandacht: er wordt op lokale elementnaam gematcht.
type listBucketResult struct {
	IsTruncated           bool
	NextContinuationToken string
	Contents              []listEntry
}

// listEntry is één object in een pagina. Alleen de key: zie [Client.List] voor
// waarom dat het antwoord is en niet een keuze die dit pakket maakt.
type listEntry struct {
	Key string
}

// List geeft de keys van elk object waarvan de key met prefix begint, in de
// lexicale orde van S3, en pagineert intern tot de listing op is.
//
// max > 0 begrenst het aantal keys; truncated zegt dan of die grens de listing
// afkapte. max <= 0 is onbegrensd — met zorg te gebruiken: een grote prefix
// wordt een grote slice, en op een node is dat de heap van iemand anders.
//
// Bewust alleen keys, geen maten of datums: dat is wat een "map" in een bucket
// nodig heeft, en een rijker resultaat zou dit pakket het antwoord laten
// bepalen dat de aanroeper hoort te kiezen.
func (c *Client) List(ctx context.Context, prefix string, max int) (keys []string, truncated bool, err error) {
	token := ""
	for {
		page, err := c.listPage(ctx, prefix, token)
		if err != nil {
			return nil, false, err
		}
		for _, item := range page.Contents {
			if max > 0 && len(keys) >= max {
				return keys, true, nil
			}
			keys = append(keys, item.Key)
		}
		if !page.IsTruncated {
			return keys, false, nil
		}
		if page.NextContinuationToken == "" {
			return nil, false, fmt.Errorf("leans3: LIST %s: truncated page without a continuation token", prefix)
		}
		token = page.NextContinuationToken
	}
}

// listPage haalt één ListObjectsV2-pagina op.
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
	// Begrensd lezen vóór het parsen: een pagina noemt maximaal 1000 keys van
	// elk maximaal 1KB, dus een correcte pagina past ruim; een vastgelopen of
	// hostiele stream mag de heap niet ongebonden laten groeien.
	const maxPage = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPage))
	if err != nil {
		return nil, fmt.Errorf("leans3: read LIST %s body: %w", prefix, err)
	}
	page, err := parseListPage(body)
	if err != nil {
		return nil, fmt.Errorf("parse LIST %s response: %w", prefix, err)
	}
	return page, nil
}
