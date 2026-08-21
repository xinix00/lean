package leans3

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

func refParse(t *testing.T, doc string) (*listBucketResult, error) {
	t.Helper()
	var ref struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		Contents              []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal([]byte(doc), &ref); err != nil {
		return nil, err
	}
	out := &listBucketResult{IsTruncated: ref.IsTruncated, NextContinuationToken: ref.NextContinuationToken}
	for _, c := range ref.Contents {
		out.Contents = append(out.Contents, listEntry{Key: c.Key})
	}
	return out, nil
}

func gelijk(a, b *listBucketResult) bool {
	if a.IsTruncated != b.IsTruncated || a.NextContinuationToken != b.NextContinuationToken ||
		len(a.Contents) != len(b.Contents) {
		return false
	}
	for i := range a.Contents {
		if a.Contents[i].Key != b.Contents[i].Key {
			return false
		}
	}
	return true
}

const echtAntwoord = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>hop-apps</Name>
  <Prefix>apps/</Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>apps/welcome/welcome.elf</Key>
    <LastModified>2026-08-12T10:00:00.000Z</LastModified>
    <ETag>&quot;9a0364b9e99bb480dd25e1f0284c8555&quot;</ETag>
    <Size>2515083</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>apps/vitals/vitals.elf</Key>
    <Size>2560201</Size>
  </Contents>
</ListBucketResult>`

func TestParseGelijkAanEncodingXML(t *testing.T) {
	docs := map[string]string{
		"echt antwoord": echtAntwoord,
		"leeg (geen Contents)": `<ListBucketResult><Name>b</Name><KeyCount>0</KeyCount>` +
			`<IsTruncated>false</IsTruncated></ListBucketResult>`,
		"afgekapt met token": `<ListBucketResult><IsTruncated>true</IsTruncated>` +
			`<NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>` +
			`<Contents><Key>a</Key></Contents></ListBucketResult>`,
		"namespace-prefix op elk element": `<s3:ListBucketResult xmlns:s3="http://x/">` +
			`<s3:IsTruncated>true</s3:IsTruncated><s3:Contents><s3:Key>met/prefix</s3:Key></s3:Contents>` +
			`</s3:ListBucketResult>`,
		"entiteiten in de key": `<ListBucketResult><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>map/a&amp;b &lt;c&gt; &quot;d&quot; &apos;e&apos;</Key></Contents></ListBucketResult>`,
		"numerieke entiteit": `<ListBucketResult><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>caf&#233;/&#x1F600;.txt</Key></Contents></ListBucketResult>`,
		"leeg element": `<ListBucketResult><IsTruncated/><Contents><Key>x</Key></Contents></ListBucketResult>`,
		"lege key":     `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key></Key></Contents></ListBucketResult>`,
		"commentaar ertussen": `<ListBucketResult><!-- door een proxy --><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>a</Key></Contents></ListBucketResult>`,
		"CDATA in de key": `<ListBucketResult><IsTruncated>false</IsTruncated>` +
			`<Contents><Key><![CDATA[raar>maar>geldig]]></Key></Contents></ListBucketResult>`,
		"attributen met > erin": `<ListBucketResult attr="a>b"><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>a</Key></Contents></ListBucketResult>`,
		"witruimte en newlines": "<ListBucketResult>\n\t<IsTruncated>\n\t\tfalse\n\t</IsTruncated>\n" +
			"\t<Contents>\n\t\t<Key>a/b</Key>\n\t</Contents>\n</ListBucketResult>\n",
		"Key ook ergens anders (mag niet meetellen)": `<ListBucketResult><IsTruncated>false</IsTruncated>` +
			`<CommonPrefixes><Key>niet-van-ons</Key></CommonPrefixes>` +
			`<Contents><Key>wel-van-ons</Key></Contents></ListBucketResult>`,
		"veel keys": veelKeys(1000),
	}
	for naam, doc := range docs {
		t.Run(naam, func(t *testing.T) {
			want, err := refParse(t, doc)
			if err != nil {
				t.Fatalf("encoding/xml leest dit document niet: %v", err)
			}
			got, err := parseListPage([]byte(doc))
			if err != nil {
				t.Fatalf("parseListPage: %v", err)
			}
			if !gelijk(got, want) {
				t.Errorf("wijkt af van encoding/xml:\n got  %+v\n want %+v", got, want)
			}
		})
	}
}

func veelKeys(n int) string {
	var b strings.Builder
	b.WriteString(`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t</NextContinuationToken>`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `<Contents><Key>apps/job-%04d/image.elf</Key><Size>%d</Size></Contents>`, i, i*1024)
	}
	b.WriteString(`</ListBucketResult>`)
	return b.String()
}

func TestParseWeigert(t *testing.T) {
	cases := map[string]string{
		"leeg":                       "",
		"geen XML":                   "niet eens een tag",
		"afgekapt midden in een tag": `<ListBucketResult><Contents><Key>a</Ke`,
		"afgekapte stream (wortel nooit gesloten)": `<ListBucketResult><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>a</Key></Contents>`,
		"sluit-tag zonder open":       `<ListBucketResult></Contents></ListBucketResult>`,
		"verkeerde sluit-tag":         `<ListBucketResult><Contents><Key>a</Contents></Key></ListBucketResult>`,
		"IsTruncated is geen boolean": `<ListBucketResult><IsTruncated>misschien</IsTruncated></ListBucketResult>`,
		"onbekende entiteit":          `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a&nbsp;b</Key></Contents></ListBucketResult>`,
		"onafgesloten entiteit":       `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a&amp</Key></Contents></ListBucketResult>`,
		"entiteit is geen teken":      `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a&#xD800;</Key></Contents></ListBucketResult>`,
		"onafgesloten commentaar":     `<ListBucketResult><!-- en dan niets meer`,
		"onafgesloten CDATA":          `<ListBucketResult><Contents><Key><![CDATA[abc</Key>`,
		"onafgesloten declaratie":     `<?xml version="1.0"`,
		"onafgesloten attribuut":      `<ListBucketResult attr="abc`,
		"lege tagnaam":                `<ListBucketResult><></></ListBucketResult>`,
		"alleen een prefix als naam":  `<ListBucketResult><s3:></s3:></ListBucketResult>`,
		"rommel in de sluit-tag":      `<ListBucketResult><Contents></Contents rommel></ListBucketResult>`,
		"inhoud na de wortel":         `<ListBucketResult></ListBucketResult><Extra/>`,
		"te diep genest":              strings.Repeat("<a>", maxDepth+1),
	}
	for naam, doc := range cases {
		t.Run(naam, func(t *testing.T) {
			if got, err := parseListPage([]byte(doc)); err == nil {
				t.Fatalf("geen fout, kreeg %+v", got)
			}
		})
	}
}

func TestParseWeigertTeVeelKeysEnTeLangeKey(t *testing.T) {
	if _, err := parseListPage([]byte(veelKeys(maxListPageKeys + 1))); err == nil ||
		!strings.Contains(err.Error(), "page exceeds") {
		t.Fatalf("te veel keys gaf %v", err)
	}
	doc := `<ListBucketResult><Contents><Key>` + strings.Repeat("k", maxS3KeyBytes+1) +
		`</Key></Contents></ListBucketResult>`
	if _, err := parseListPage([]byte(doc)); err == nil || !strings.Contains(err.Error(), "key exceeds") {
		t.Fatalf("te lange key gaf %v", err)
	}
	doc = `<ListBucketResult><NextContinuationToken>` + strings.Repeat("t", maxListToken+1) +
		`</NextContinuationToken></ListBucketResult>`
	if _, err := parseListPage([]byte(doc)); err == nil || !strings.Contains(err.Error(), "token exceeds") {
		t.Fatalf("te lange continuation token gaf %v", err)
	}
}

func TestAfgekaptAntwoordIsAltijdEenFout(t *testing.T) {
	for i := 1; i < len(echtAntwoord); i++ {
		half := echtAntwoord[:i]
		_, refErr := refParse(t, half)
		_, err := parseListPage([]byte(half))
		if refErr == nil {
			continue
		}
		if err == nil {
			t.Fatalf("afgekapt op %d bytes gaf geen fout, encoding/xml wel:\n%q", i, half)
		}
	}
}

func TestIsTruncatedVarianten(t *testing.T) {

	for doc, wil := range map[string]bool{
		`<r><IsTruncated>1</IsTruncated></r>`:      true,
		`<r><IsTruncated>0</IsTruncated></r>`:      false,
		`<r><IsTruncated>true</IsTruncated></r>`:   true,
		`<r><IsTruncated>false</IsTruncated></r>`:  false,
		`<r><IsTruncated> true </IsTruncated></r>`: true,
		`<r></r>`: false,
	} {
		got, err := parseListPage([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		if got.IsTruncated != wil {
			t.Errorf("%s: IsTruncated = %v, wilde %v", doc, got.IsTruncated, wil)
		}
	}
}

func BenchmarkParseListPage1000(b *testing.B) {
	doc := []byte(veelKeys(1000))
	b.SetBytes(int64(len(doc)))
	for i := 0; i < b.N; i++ {
		if _, err := parseListPage(doc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodingXML1000(b *testing.B) {
	doc := []byte(veelKeys(1000))
	b.SetBytes(int64(len(doc)))
	var ref struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		Contents              []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	for i := 0; i < b.N; i++ {
		if err := xml.Unmarshal(doc, &ref); err != nil {
			b.Fatal(err)
		}
	}
}
