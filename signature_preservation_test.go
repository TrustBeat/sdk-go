package trustbeat_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrustBeat/sdk-go"
)

const spSubmission = `{"submission_version":1,"extractor":{"name":"trustbeat-signature","version":"1.0.0"},` +
	`"container":{"format":"PAdES","name":"contract.pdf","size_bytes":10,"digests":{"sha256":"aa","sha512":"bb","sha3-512":"cc"}},` +
	`"data_objects":[],"signatures":[{"format":"CAdES","source":"pdf","signature_b64":"MA==","binding":[]}],"timestamps":[]}`

const spRecord = `{"id":"01REC","status":"pending","created_at":"2026-10-13T10:00:00Z","client_ref":"contract-17",` +
	`"container":{"format":"PAdES","name":"contract.pdf","sha256":"aa"},"signature_count":1,` +
	`"peo":{"sha256":"dd","sha512":"ee"},` +
	`"preservation":{"profile":"https://trustbeat.eu/preservation/profile/pds-wst-v1","profile_status":"draft","preserve_until":"2056-10-13T10:00:00Z"},` +
	`"evidence_record":{"status":"pending"},"signatures":[{"index":0,"format":"CAdES","indication":"TOTAL_PASSED"}]}`

const spReport = `{"report_version":1,"record_id":"01REC","result":"failed","claim":"At least one step failed.",` +
	`"steps":[{"step":1,"name":"file","title":"The presented file is the preserved file","result":"failed","checked_by":["extractor"],"details":["The digests differ."]}],` +
	`"signatures":[],"evidence_record":[]}`

type spCall struct {
	method, uri, contentType string
	body                     []byte
}

// spServer answers every request with status, contentType and body, and records the requests.
func spServer(t *testing.T, status int, contentType, body string) (*httptest.Server, *[]spCall) {
	t.Helper()
	calls := &[]spCall{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*calls = append(*calls, spCall{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), b})
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		w.Write([]byte(body)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

func sameJSON(t *testing.T, a, b []byte) {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		t.Fatalf("not JSON: %s / %s", a, b)
	}
	xs, _ := json.Marshal(x)
	ys, _ := json.Marshal(y)
	if string(xs) != string(ys) {
		t.Fatalf("body changed:\n%s\n%s", xs, ys)
	}
}

func TestPreserveSignaturesSendsTheSubmissionUnchanged(t *testing.T) {
	srv, calls := spServer(t, 202, "application/json", spRecord)
	rec, err := newClient(t, srv).PreserveSignatures(context.Background(), []byte(spSubmission),
		&trustbeat.PreserveOptions{ClientRef: "contract 17/a"})
	if err != nil {
		t.Fatal(err)
	}
	c := (*calls)[0]
	if c.method != "POST" || c.uri != "/v1/signature-preservation?client_ref=contract+17%2Fa" || c.contentType != "application/json" {
		t.Fatalf("%+v", c)
	}
	sameJSON(t, c.body, []byte(spSubmission))
	if rec.ID != "01REC" || rec.Status != "pending" || rec.Container.Format != "PAdES" || rec.PEO.SHA256 != "dd" ||
		rec.ClientRef == nil || *rec.ClientRef != "contract-17" || rec.Preservation.PreserveUntil != "2056-10-13T10:00:00Z" ||
		rec.EvidenceRecord.DownloadURL != nil || rec.Signatures[0]["indication"] != "TOTAL_PASSED" {
		t.Fatalf("%+v", rec)
	}
}

func TestPreserveSignaturesNeedsAJSONObject(t *testing.T) {
	srv, calls := spServer(t, 202, "application/json", spRecord)
	for _, bad := range []string{"[1,2]", "not json", "null"} {
		if _, err := newClient(t, srv).PreserveSignatures(context.Background(), []byte(bad), nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("a bad submission was sent")
	}
}

func TestInvalidSubmissionCarriesTheCode(t *testing.T) {
	srv, _ := spServer(t, 400, "application/json", `{"error":{"code":"INVALID_SUBMISSION","message":"binding"}}`)
	_, err := newClient(t, srv).PreserveSignatures(context.Background(), []byte(spSubmission), nil)
	var te *trustbeat.TrustBeatError
	if !errors.As(err, &te) || te.Status != 400 || te.ErrorCode != "INVALID_SUBMISSION" {
		t.Fatalf("%v", err)
	}
}

func TestGetAndListSignaturePreservations(t *testing.T) {
	srv, calls := spServer(t, 200, "application/json", strings.Replace(spRecord,
		`"evidence_record":{"status":"pending"}`, `"evidence_record":{"status":"ready","download_url":"https://x/evidence-record.ers"}`, 1))
	rec, err := newClient(t, srv).GetSignaturePreservation(context.Background(), "01REC")
	if err != nil || (*calls)[0].uri != "/v1/signature-preservation/01REC" || rec.EvidenceRecord.Status != "ready" ||
		rec.EvidenceRecord.DownloadURL == nil {
		t.Fatalf("%v %+v", err, rec)
	}
	srv2, calls2 := spServer(t, 200, "application/json", `{"records":[`+spRecord+`]}`)
	recs, err := newClient(t, srv2).ListSignaturePreservations(context.Background(), 10)
	if err != nil || len(recs) != 1 || (*calls2)[0].uri != "/v1/signature-preservation?limit=10" {
		t.Fatalf("%v %v", err, recs)
	}
}

func TestSignaturePreservationNotFound(t *testing.T) {
	srv, _ := spServer(t, 404, "application/json", `{"error":{"code":"NOT_FOUND","message":"Record not found."}}`)
	c := newClient(t, srv)
	ctx := context.Background()
	_, e1 := c.GetSignaturePreservation(ctx, "nope")
	_, e2 := c.DownloadSignaturePreservationPackage(ctx, "nope")
	_, e3 := c.VerifySignaturePreservationPDF(ctx, "nope", []byte(spSubmission))
	for i, err := range []error{e1, e2, e3} {
		var nf *trustbeat.NotFoundError
		if !errors.As(err, &nf) {
			t.Errorf("%d: %v", i, err)
		}
	}
}

func TestDownloadSignaturePreservationPackage(t *testing.T) {
	srv, calls := spServer(t, 200, "application/zip", "PK\x03\x04zip")
	b, err := newClient(t, srv).DownloadSignaturePreservationPackage(context.Background(), "01REC")
	if err != nil || string(b) != "PK\x03\x04zip" || (*calls)[0].uri != "/v1/signature-preservation/01REC/package" {
		t.Fatalf("%v %q", err, b)
	}
}

func TestVerifySignaturePreservation(t *testing.T) {
	srv, calls := spServer(t, 200, "application/json", spReport)
	rep, err := newClient(t, srv).VerifySignaturePreservation(context.Background(), "01REC", []byte(spSubmission))
	if err != nil {
		t.Fatal(err)
	}
	if (*calls)[0].uri != "/v1/signature-preservation/01REC/verify" {
		t.Fatal((*calls)[0].uri)
	}
	sameJSON(t, (*calls)[0].body, []byte(spSubmission))
	if rep.Result != "failed" || rep.Steps[0].Name != "file" || rep.Steps[0].CheckedBy[0] != "extractor" || !strings.Contains(string(rep.Raw), `"report_version":1`) {
		t.Fatalf("%+v", rep)
	}
}

func TestVerifySignaturePreservationPDF(t *testing.T) {
	srv, calls := spServer(t, 200, "application/pdf", "%PDF-1.7")
	pdf, err := newClient(t, srv).VerifySignaturePreservationPDF(context.Background(), "01REC", []byte(spSubmission))
	if err != nil || string(pdf) != "%PDF-1.7" {
		t.Fatalf("%v %q", err, pdf)
	}
	c := (*calls)[0]
	if c.method != "POST" || c.uri != "/v1/signature-preservation/01REC/verify?format=pdf" || c.contentType != "application/json" {
		t.Fatalf("%+v", c)
	}
	sameJSON(t, c.body, []byte(spSubmission))
}
