package bunny

import "testing"

// A zone holding a TLSA record must stay listable: an unmapped type ID makes
// every GetRecords call fail.
func Test_TLSARecordType(t *testing.T) {
	name, err := fromBunnyType(bunnyTypeTLSA)
	if err != nil || name != "TLSA" {
		t.Fatalf("fromBunnyType(15) = %q, %v", name, err)
	}
	if id, err := toBunnyType("TLSA"); err != nil || id != 15 {
		t.Fatalf("toBunnyType(TLSA) = %d, %v", id, err)
	}
	rec, err := bunnyZone{}.libdnsRecord(bunnyRecord{Type: bunnyTypeTLSA, Name: "_25._tcp.mx", Value: "3 1 1 abcd"})
	if err != nil || rec.RR().Type != "TLSA" || rec.RR().Data != "3 1 1 abcd" {
		t.Fatalf("libdnsRecord = %+v, %v", rec, err)
	}
}
