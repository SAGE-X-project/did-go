package testutil

// Fixture documents. ExampleDoc is a DID 1.1 representation of ExampleDID
// (application/did) with relative ids, two services and an extension map;
// ExampleDocV10 is a DID Core 1.0 JSON-LD representation
// (application/did+ld+json) of a document with absolute ids.
const (
	ExampleDID = "did:example:123"
	// ExampleKey is a Multikey value from DID Resolution v1.0 Example 11.
	ExampleKey = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
	ExampleDoc = `{
  "@context": ["https://www.w3.org/ns/did/v1.1", "https://ext.example/v1"],
  "id": "did:example:123",
  "verificationMethod": [{
    "id": "#key-1", "type": "Multikey", "controller": "did:example:123",
    "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
  }, {
    "id": "did:example:123#key-2", "type": "Multikey", "controller": "did:example:123",
    "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
  }],
  "authentication": ["#key-1", {
    "id": "#key-3", "type": "Multikey", "controller": "did:example:123",
    "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
  }],
  "assertionMethod": ["did:example:123#key-2"],
  "service": [{
    "id": "#messages", "type": "DIDCommMessaging",
    "serviceEndpoint": "https://example.com/messages/8377464"
  }, {
    "id": "did:example:123#files", "type": ["FileService", "Storage"],
    "serviceEndpoint": ["https://files.example/a/b", {"uri": "https://map.example/"}, "https://files.example/c#top"]
  }, {
    "id": "#map", "type": "MapService", "serviceEndpoint": {"uri": "https://map.example/"}
  }],
  "linkedResource": {"id": "#res-1", "items": [{"id": "#res-2", "name": "two"}, "#plain"]}
}`
	ExampleDocV10 = `{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:example:123",
  "verificationMethod": [{
    "id": "did:example:123#key-1", "type": "Multikey", "controller": "did:example:123"
  }],
  "authentication": ["did:example:123#key-1"],
  "service": [{"id": "did:example:123#files", "type": "FileService", "serviceEndpoint": "https://files.example/"}]
}`
)
