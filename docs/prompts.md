## Q1
I'd like to tweak the entry schema, the resolved identifier. I want the id schema to have two logical parts

{log storage path}/{entry-id}

The entry id I'm considering is should be the hex reprsentation of the byte encoding:

idtimestamp - 8bytes (big endian msb first zero padded)
mmrIndex - 8 bytes (big endian msb first zero padded)
contentHash - 32 bytes

And at the api surface, represented as a single hex encoded string, opaque to the api, but with publicly documented structure

The log storage path portions would be the logId/massifHeight

This separation conveys that *either* idtimestamp or mmrIndex are canonical entry locators given the log id. the massifHeight can always be inferrd. some logs may get organised into multiple storage organizations such that the same entry is collated in multiple organisations.

A consequence of this is that instead of
/entries/{massifHeight}/{mmrIndex}/{idtimestampHex}/receipt

I want

/entries/{logPath}/{entryId}/receipt

For resolve-reciept

And /entries/{logPath}/entryId} as the canonical permanent api identifier for an entry

Can you assess this change, provide an opinion even if is that this is largely netraul or cosmetic.

Some issues I'm considering:
- the convenience of being able to recover logId, massifHeight, mmrIndex and idTimestamp without baking it permanently into the api or the canonical identifier scheme
- the natural time ordered nature of the entryId versus database hotspot issues - ie content hash first or last
- whether this can be considered strictly aligned with the draft or not

## A1

I’ll assess the new “opaque entryId” scheme against the current implementation and SCRAPI semantics, and I’ll sanity-check the draft’s 2.1.3/2.1.4 endpoint shapes so we can talk precisely about “aligned” vs “custom”.
Opinion (net impact)
This change is mostly a packaging/API-contract change, but it’s net positive if your goal is: keep the HTTP identifier stable while allowing storage/layout changes later. It’s not purely cosmetic because it changes how much meaning your route shape commits to, and it has some key-ordering implications depending on where you use the identifier (URLs only vs DB keys).
What you gain
Decouple URL shape from internal fields: /entries/{logPath}/{entryId} reads like “opaque entry token under a storage namespace”, which is easier to evolve than committing to N positional URL segments forever.
Still recoverable when needed: because the entryId has a documented fixed-width encoding, anyone can recover:
idtimestamp = first 8 bytes
mmrIndex = next 8 bytes
contentHash = last 32 bytes
without needing URL segment semantics.
Clear separation of concerns:
logPath = logId/massifHeight = “which log + which storage layout”
entryId = “which entry (with redundant locators)”
Future multi-organization story is clearer: you can imagine adding more logPath variants (e.g., different storage layouts) without redefining the entryId itself.
Trade-offs / gotchas
Longer identifiers: 48 bytes → 96 hex chars. That’s fine for URLs, but it’s a usability hit vs separate segments.
You’re not really removing coupling—just moving it: the system still relies on idtimestamp/mmrIndex/contentHash; you’ve just made them encoded rather than positional.
Validation becomes “all-or-nothing”: if the API truly treats entryId as opaque, it can only validate “hex + length”. If you want strong guarantees, you’ll still end up decoding it internally (even if you don’t expose separate path params).
Versioning: without an explicit version, any future tweak to the byte layout is painful. (Length-based inference works, but is brittle.)
Your specific issues
Recover logId/massifHeight/mmrIndex/idtimestamp without baking into the API
This scheme does that reasonably well: the API surface only needs {logPath}/{entryId}, yet the public spec can document how to decode entryId.
Minor nuance: you are still “baking” those fields into the canonical identifier, just not into the route shape.
Time-ordered entryId vs hotspot concerns (content hash first/last)
With idtimestamp first (and mmrIndex second), the hex string is roughly time-ordered lexicographically. That’s great for human/debug ordering and range scans.
Hotspot risk depends on where you use it:
If it’s only a URL token (and storage is still massif-based), hotspot risk is basically irrelevant.
If you start using entryId as a primary DB/KV key in a system that shards by prefix or has “right-edge” insert costs, then time-first keys can hotspot.
Mitigations that don’t change your canonical entryId:
Add an entropy prefix in the storage path, e.g. store under .../entries/{entryId[0:4]}/{entryId}.
Or keep storage keyed by something random-ish (contentHash) and use entryId as a secondary identifier.
Strict alignment with the SCRAPI draft
SCRAPI’s identifiers are intended to be opaque tokens; packing into a single entryId is arguably more in-spirit than exposing multiple positional params. But your overall route structure (extra logId, and now logPath) is still a customization. I’d describe it as SCRAPI-inspired semantics, not strict endpoint-template compliance. Reference: .
Small recommendation
Add a version nibble/byte to the encoded entryId (or a v1 path component) so you can evolve the encoding later without breaking canonical IDs. For example: entryId = hex( 0x01 || idts_be8 || mmr_be8 || hash32 ) (adds 2 hex chars, buys you a lot of future-proofing).
I think filecoin and ipfs might have an encoding of hashes scheme that has some applicable ideas here can you research what that might be and recomend if adoptoin makes sense - it would have to retain the ability to encode everything we need

I’ll pull up the relevant IPFS/Filecoin “multiformats” pieces (CID, multibase, multicodec, multihash) and then map them directly onto your need: a single opaque string that can still decode idtimestamp/mmrIndex/contentHash.
What IPFS/Filecoin are doing that’s relevant
Multihash: a self-describing hash encoding: (hash-function-code, digest-length, digest-bytes) (codes/lengths are varints). This lets an identifier carry “this digest is sha2-256, 32 bytes” rather than assuming it out-of-band. See Filecoin’s multiformats overview and IPFS-oriented explanations: Filecoin multiformats, Multihash article.
CID: a content-addressed identifier that wraps a multihash plus version/codec/base information. It’s designed to identify some content by its hash, not to carry arbitrary fields. See IPFS content addressing (and Filecoin’s multiformats/IPLD notes: Filecoin multiformats, Filecoin IPLD).
Does adopting these make sense for your entryId?
Adopt Multihash for contentHash: Yes, if you want algorithm agility (e.g., future sha2-512/blake3) without changing the entryId semantics. Instead of always assuming “32 bytes sha256”, you encode that fact into the bytes. This is the most directly applicable “IPFS/Filecoin idea”.
Cost: a small prefix (function code + length) and slightly longer string representation.
Adopt CID for the whole {idtimestamp, mmrIndex, contentHash} tuple: Mostly no, because a CID normally contains only a hash digest (plus metadata). If you make a CID of the tuple-bytes, the CID will not let you recover idtimestamp/mmrIndex without separately having the original bytes (that’s inherent to content-addressing) 1.
A practical “multiformats-inspired” recommendation (keeps your decodability)
Keep your core idea (a single opaque string with documented decoding), but steal the multihash self-description:
Binary layout (suggested):
version (1 byte or varint)
idtimestamp (8 bytes, big-endian)
mmrIndex (8 bytes, big-endian)
contentHash as multihash (so it’s {alg,length,digest} rather than raw 32 bytes)
This retains everything you need inside the identifier, and adds the main future-proofing benefit IPFS/Filecoin get from multihash (Filecoin multiformats, Multihash article).
Encoding-order / hotspot note (in your context)
Multihash doesn’t really change your hotspot story; that depends on what you use as a storage key. If entryId ever becomes a primary KV/DB key and it begins with time (idtimestamp), that can hotspot; if it’s mostly an HTTP identifier and your storage remains massif-based, it’s usually a non-issue.
If you want, tell me whether you want to keep hex as the public representation or are open to a base encoding like CIDs use (the CID concept page talks about multibase/encoding prefixes too: IPFS content addressing).


cursor agent to run Agent • ⌘K to generate command


